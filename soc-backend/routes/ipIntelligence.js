const express = require("express");
const router  = express.Router();
const axios   = require("axios");
const db      = require("../database");
const store   = require("../data/store");

const CATEGORY_MAP = { 4:"DDoS Attack",5:"FTP Brute Force",9:"Open Proxy",14:"Port Scan",15:"Hacking",16:"SQL Injection",18:"Brute Force",19:"Bad Web Bot",21:"Web App Attack",22:"SSH Brute Force" };

router.get("/blocked/list", async (req, res) => {
  try {
    const ips = await db.getBlockedIPs();
    res.json({ blockedIPs: ips, total: ips.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch blocked IPs" });
  }
});

router.post("/block", async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "ip is required" });
  try {
    await db.blockIP(ip, "Manual block", "admin");
    store.blockedIPs.add(ip);
    res.json({ success: true, message: `IP ${ip} blocked` });
  } catch (err) {
    res.status(500).json({ error: "Failed to block IP" });
  }
});

router.delete("/block/:ip", async (req, res) => {
  try {
    await db.unblockIP(req.params.ip);
    store.blockedIPs.delete(req.params.ip);
    store.bruteForceTracker.delete(req.params.ip);
    store.rateLimitTracker.delete(req.params.ip);
    store.attackThresholdTracker.delete(req.params.ip); // Clear attack threshold tracking too
    res.json({ success: true, message: `IP ${req.params.ip} unblocked` });
  } catch (err) {
    res.status(500).json({ error: "Failed to unblock IP" });
  }
});

// NEW: Get attack threshold counts for all IPs being tracked
router.get("/threshold/monitor", (req, res) => {
  try {
    const now = Date.now();
    const monitoring = [];
    
    for (const [ip, ipTracker] of store.attackThresholdTracker.entries()) {
      const attacks = {};
      for (const [attackType, entry] of ipTracker.entries()) {
        const timeRemaining = Math.max(0, Math.ceil((5 * 60 * 1000 - (now - entry.firstAttempt)) / 1000));
        attacks[attackType] = {
          count: entry.count,
          firstAttempt: new Date(entry.firstAttempt),
          timeRemainingSeconds: timeRemaining,
          recentAttacks: entry.attacks.slice(-5).map(t => new Date(t))
        };
      }
      
      if (Object.keys(attacks).length > 0) {
        monitoring.push({
          ip,
          isBlocked: store.blockedIPs.has(ip),
          attacks
        });
      }
    }
    
    res.json({ 
      totalIPsTracked: monitoring.length,
      trackedIPs: monitoring.sort((a, b) => {
        const aTotal = Object.values(a.attacks).reduce((sum, atk) => sum + atk.count, 0);
        const bTotal = Object.values(b.attacks).reduce((sum, atk) => sum + atk.count, 0);
        return bTotal - aTotal;
      })
    });
  } catch (err) {
    console.error("Threshold monitor error:", err);
    res.status(500).json({ error: "Failed to fetch threshold monitoring data" });
  }
});

router.get("/:ip", async (req, res) => {
  const { ip } = req.params;
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4.test(ip)) return res.status(400).json({ error: "Invalid IP address" });

  try {
    const [localActivity, blockedList] = await Promise.all([
      db.getIPActivity(ip),
      db.getBlockedIPs(),
    ]);
    localActivity.isBlockedLocally = blockedList.includes(ip);

    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey || apiKey === "your_abuseipdb_api_key_here") {
      return res.json({ ip, source: "local_only", warning: "AbuseIPDB key not configured.", abuseConfidenceScore: Math.min(localActivity.blockedLocally * 10, 99), ...localActivity });
    }

    const response = await axios({ method: "GET", url: "https://api.abuseipdb.com/api/v2/check", params: { ipAddress: ip, maxAgeInDays: 90 }, headers: { Accept: "application/json", Key: apiKey }, timeout: 8000 });
    const d = response.data.data;
    res.json({ ip: d.ipAddress, source: "abuseipdb", abuseConfidenceScore: d.abuseConfidenceScore, countryCode: d.countryCode, countryName: d.countryName, isp: d.isp, domain: d.domain, isTor: d.isTor || false, isVPN: d.usageType === "VPN Service", totalReports: d.totalReports, lastReportedAt: d.lastReportedAt, ...localActivity });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch IP intelligence" });
  }
});

router.get("/:ip/history", async (req, res) => {
  try {
    const alerts = await db.getAlertsByIP(req.params.ip, 50);
    res.json({ ip: req.params.ip, alerts, total: alerts.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch IP history" });
  }
});

module.exports = router;
