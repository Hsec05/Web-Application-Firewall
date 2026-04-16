const express = require("express");
const router  = express.Router();
const { v4: uuidv4 } = require("uuid");
const db      = require("../database");
const store   = require("../data/store");

// GET /api/alerts
router.get("/", async (req, res) => {
  try {
    const { ip, severity, attackType, action, from, to, page = 1, limit = 100 } = req.query;
    const { rows, total } = await db.getAlerts({ ip, severity, attackType, action, from, to, page, limit });
    const pageNum  = parseInt(page);
    const limitNum = parseInt(limit);
    res.json({ data: rows, total, page: pageNum, limit: limitNum, pages: Math.ceil(total / limitNum) });
  } catch (err) {
    console.error("Alerts error:", err.message);
    res.status(500).json({ error: "Failed to fetch alerts" });
  }
});

// GET /api/alerts/live
router.get("/live", async (req, res) => {
  try {
    const rows = await db.getLiveAlerts(20);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch live alerts" });
  }
});

// GET /api/alerts/stats/summary
router.get("/stats/summary", async (req, res) => {
  try {
    const stats = await db.getDashboardStats();
    res.json({
      total:   stats.totalRequests,
      blocked: stats.blockedRequests,
      allowed: stats.totalRequests - stats.blockedRequests,
      byAttackType: stats.topAttackTypes,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// GET /api/alerts/:id
router.get("/:id", async (req, res) => {
  try {
    const alert = await db.getAlertById(req.params.id);
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    res.json(alert);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch alert" });
  }
});

// POST /api/alerts — manual ingest
router.post("/", async (req, res) => {
  const { attackType, sourceIP, targetURL, severity, action, country, countryCode, requestMethod, userAgent, payload, ruleId, ruleName } = req.body;
  if (!sourceIP || !attackType) return res.status(400).json({ error: "sourceIP and attackType are required" });

  const newAlert = {
    id: uuidv4(), timestamp: new Date(), attackType, sourceIP,
    targetURL: targetURL || "/unknown", severity: severity || "medium",
    action: action || "blocked", country: country || "Unknown",
    countryCode: countryCode || "XX", requestMethod: requestMethod || "GET",
    userAgent, payload, ruleId, ruleName,
  };

  try {
    await db.insertAlert(newAlert);
    store.alerts.unshift(newAlert);
    if (store.alerts.length > 500) store.alerts.pop();
    res.status(201).json(newAlert);
  } catch (err) {
    res.status(500).json({ error: "Failed to save alert" });
  }
});

module.exports = router;
