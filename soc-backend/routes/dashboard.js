const express = require("express");
const router  = express.Router();
const db      = require("../database");
const store   = require("../data/store");

router.get("/", async (req, res) => {
  try {
    const stats = await db.getDashboardStats();
    const activeIncidents = (await db.getIncidents()).filter(
      i => i.status === "open" || i.status === "investigating"
    ).length;
    res.json({ ...stats, activeIncidents });
  } catch (err) {
    console.error("Dashboard error:", err.message);
    res.status(500).json({ error: "Failed to load dashboard stats" });
  }
});

module.exports = router;
