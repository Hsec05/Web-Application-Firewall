const express = require("express");
const router  = express.Router();
const db      = require("../database");

router.get("/", async (req, res) => {
  try {
    const { from, to } = req.query;
    const data = await db.getAnalytics(from, to);
    res.json(data);
  } catch (err) {
    console.error("Analytics error:", err.message);
    res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

module.exports = router;
