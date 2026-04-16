const express = require("express");
const router  = express.Router();
const { v4: uuidv4 } = require("uuid");
const db      = require("../database");
const { writeAuditLog } = require("./auditLogs");

// ── Soft auth middleware — extracts user from JWT if present ───────────────────
function extractUser(req, res, next) {
  let jwt;
  try { jwt = require("jsonwebtoken"); } catch { return next(); }
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    try {
      req.authUser = jwt.verify(
        authHeader.slice(7),
        process.env.JWT_SECRET || "soc-dashboard-super-secret-key-change-in-prod"
      );
    } catch { /* invalid token — proceed as anonymous */ }
  }
  next();
}

router.get("/", async (req, res) => {
  try {
    const { status, severity } = req.query;
    const results = await db.getIncidents({ status, severity });
    const summary = {
      open:          results.filter(i => i.status === "open").length,
      investigating: results.filter(i => i.status === "investigating").length,
      resolved:      results.filter(i => i.status === "resolved").length,
      closed:        results.filter(i => i.status === "closed").length,
    };
    res.json({ data: results, total: results.length, summary });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch incidents" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const incident = await db.getIncidentById(req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    res.json(incident);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch incident" });
  }
});

// BUG FIX: PATCH was missing extractUser and audit logging entirely.
// Any status change (open → investigating → resolved → closed) is now
// written to soc_audit_log so admins can see the full activity trail.
router.patch("/:id", extractUser, async (req, res) => {
  try {
    // Snapshot the old status before we overwrite it
    const before  = await db.getIncidentById(req.params.id);
    if (!before) return res.status(404).json({ error: "Incident not found" });

    const updated = await db.updateIncident(req.params.id, req.body);

    // Log any status transition
    if (req.body.status && req.body.status !== before.status) {
      writeAuditLog({
        userId:    req.authUser?.id,
        username:  req.authUser?.username || "analyst",
        role:      req.authUser?.role     || "analyst",
        action:    "incident_status_changed",
        category:  "incident",
        target:    before.title || req.params.id,
        targetId:  req.params.id,
        detail: {
          from:      before.status,
          to:        req.body.status,
          assignee:  req.body.assignee ?? before.assignee,
          notes:     req.body.notes    ?? undefined,
        },
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        outcome:   "success",
      }).catch(() => {});
    }

    // Log assignee change separately if that's what changed
    if (req.body.assignee !== undefined && req.body.assignee !== before.assignee) {
      writeAuditLog({
        userId:    req.authUser?.id,
        username:  req.authUser?.username || "analyst",
        role:      req.authUser?.role     || "analyst",
        action:    "incident_assignee_changed",
        category:  "incident",
        target:    before.title || req.params.id,
        targetId:  req.params.id,
        detail: { from: before.assignee, to: req.body.assignee },
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        outcome:   "success",
      }).catch(() => {});
    }

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update incident" });
  }
});

router.post("/", extractUser, async (req, res) => {
  try {
    const incident = {
      id: `INC-${Date.now()}`,
      ...req.body,
      status: req.body.status || "open",
    };
    await db.upsertIncident(incident);

    writeAuditLog({
      userId:    req.authUser?.id,
      username:  req.authUser?.username || "analyst",
      role:      req.authUser?.role     || "analyst",
      action:    "incident_created",
      category:  "incident",
      target:    incident.title || incident.id,
      targetId:  incident.id,
      detail:    { severity: incident.severity, status: incident.status },
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      outcome:   "success",
    }).catch(() => {});

    res.status(201).json(incident);
  } catch (err) {
    res.status(500).json({ error: "Failed to create incident" });
  }
});

module.exports = router;
