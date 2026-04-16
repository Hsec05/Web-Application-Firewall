const express = require("express");
const router  = express.Router();
const db      = require("../database");
const { writeAuditLog } = require("./auditLogs");
const wafMiddleware = require("../middleware/wafMiddleware");

// ── Soft auth middleware — extracts user from JWT if present, doesn't enforce role ──
function extractUser(req, res, next) {
  let jwt;
  try { jwt = require("jsonwebtoken"); } catch { return next(); }
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    try {
      req.authUser = jwt.verify(authHeader.slice(7), process.env.JWT_SECRET || "soc-dashboard-super-secret-key-change-in-prod");
    } catch { /* invalid token — proceed as anonymous */ }
  }
  next();
}

router.get("/", async (req, res) => {
  try {
    const rules = await db.getRules();
    res.json({ data: rules, total: rules.length, active: rules.filter(r => r.enabled).length });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch rules" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const rule = await db.getRuleById(req.params.id);
    if (!rule) return res.status(404).json({ error: "Rule not found" });
    res.json(rule);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch rule" });
  }
});

router.patch("/:id", extractUser, async (req, res) => {
  try {
    const updated = await db.updateRule(req.params.id, req.body);
    if (!updated) return res.status(404).json({ error: "Rule not found" });
    wafMiddleware.invalidateRulesCache(); // WAF picks up changes immediately
    writeAuditLog({
      userId: req.authUser?.id, username: req.authUser?.username || "system",
      role: req.authUser?.role || "analyst",
      action: "rule_updated", category: "rule",
      target: updated.name || req.params.id, targetId: req.params.id,
      detail: req.body, ipAddress: req.ip, outcome: "success",
    }).catch(() => {});
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update rule" });
  }
});

router.post("/:id/toggle", extractUser, async (req, res) => {
  try {
    const rule = await db.getRuleById(req.params.id);
    if (!rule) return res.status(404).json({ error: "Rule not found" });
    const updated = await db.updateRule(req.params.id, { enabled: !rule.enabled });
    wafMiddleware.invalidateRulesCache(); // WAF picks up enable/disable immediately
    writeAuditLog({
      userId: req.authUser?.id, username: req.authUser?.username || "system",
      role: req.authUser?.role || "analyst",
      action: updated.enabled ? "rule_enabled" : "rule_disabled", category: "rule",
      target: updated.name || req.params.id, targetId: req.params.id,
      detail: { enabled: updated.enabled }, ipAddress: req.ip, outcome: "success",
    }).catch(() => {});
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to toggle rule" });
  }
});

router.post("/", extractUser, async (req, res) => {
  try {
    const { name, category, description, threshold, severity, action } = req.body;
    if (!name || !category) return res.status(400).json({ error: "name and category are required" });
    const newRule = await db.createRule({
      id: `rule-${category.toLowerCase().replace(/\s+/g,"-")}-${Date.now()}`,
      name, category, description, threshold, severity, action,
    });
    wafMiddleware.invalidateRulesCache(); // WAF picks up new rule immediately
    writeAuditLog({
      userId: req.authUser?.id, username: req.authUser?.username || "system",
      role: req.authUser?.role || "analyst",
      action: "rule_created", category: "rule",
      target: name, detail: req.body, ipAddress: req.ip, outcome: "success",
    }).catch(() => {});
    res.status(201).json(newRule);
  } catch (err) {
    res.status(500).json({ error: "Failed to create rule" });
  }
});

router.delete("/:id", extractUser, async (req, res) => {
  try {
    if (req.params.id.startsWith("rule-sqli") || req.params.id.startsWith("rule-xss")) {
      return res.status(403).json({ error: "Cannot delete core WAF rules" });
    }
    const deleted = await db.deleteRule(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Rule not found" });
    wafMiddleware.invalidateRulesCache(); // WAF drops deleted rule immediately
    writeAuditLog({
      userId: req.authUser?.id, username: req.authUser?.username || "system",
      role: req.authUser?.role || "analyst",
      action: "rule_deleted", category: "rule",
      target: deleted.name || req.params.id, targetId: req.params.id,
      ipAddress: req.ip, outcome: "success",
    }).catch(() => {});
    res.json({ success: true, deleted });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete rule" });
  }
});

module.exports = router;
