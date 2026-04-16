/**
 * Threat Map Route
 * Provides geo-enriched attack event data for the live threat map visualization.
 */

const express = require("express");
const router  = express.Router();
const db      = require("../database");

/**
 * GET /api/threat-map
 * Returns recent threat events with coordinates for map rendering.
 *
 * Query params:
 *   minutes  - lookback window in minutes (default: 60, max: 1440)
 *   limit    - max events to return     (default: 200, max: 500)
 *   action   - filter by "blocked" | "allowed" | "all" (default: "all")
 */
router.get("/", async (req, res) => {
  try {
    const minutes = Math.min(parseInt(req.query.minutes) || 60, 1440);
    const limit   = Math.min(parseInt(req.query.limit)   || 200, 500);
    const action  = req.query.action || "all";

    const data = await db.getThreatMapEvents({ minutes, limit, action });
    res.json(data);
  } catch (err) {
    console.error("Threat map route error:", err.message);
    res.status(500).json({ error: "Failed to fetch threat map data" });
  }
});

/**
 * GET /api/threat-map/summary
 * Returns aggregated stats per country for the heatmap layer.
 */
router.get("/summary", async (req, res) => {
  try {
    const minutes = Math.min(parseInt(req.query.minutes) || 60, 1440);
    const summary = await db.getThreatMapSummary({ minutes });
    res.json(summary);
  } catch (err) {
    console.error("Threat map summary error:", err.message);
    res.status(500).json({ error: "Failed to fetch threat map summary" });
  }
});

module.exports = router;
