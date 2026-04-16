/**
 * System Settings Routes — Admin-only WAF configuration
 * Controls thresholds, whitelisted IPs, alert destinations, rate limits, integrations.
 */

const express = require("express");
const router  = express.Router();
const db      = require("../database");
const { writeAuditLog } = require("./auditLogs");
const wafConfig = require("../wafConfig");
const store     = require("../data/store");

// ── Ensure settings table exists ───────────────────────────────────────────────
async function ensureSettingsTable() {
  await db.pool.query(`
    CREATE TABLE IF NOT EXISTS soc_settings (
      key         VARCHAR(120) PRIMARY KEY,
      value       JSONB        NOT NULL,
      description TEXT,
      category    VARCHAR(60)  NOT NULL DEFAULT 'general',
      updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_by  VARCHAR(80)
    );
  `);

  // Seed defaults if table is empty
  const { rows } = await db.pool.query("SELECT COUNT(*) FROM soc_settings");
  if (parseInt(rows[0].count) === 0) {
    const defaults = [
      // WAF Thresholds
      { key: "waf.block_threshold",   value: JSON.stringify(5),     category: "thresholds",   description: "Number of rule matches before an IP is auto-blocked" },
      { key: "waf.log_threshold",     value: JSON.stringify(2),     category: "thresholds",   description: "Number of matches before switching from log to monitor mode" },
      { key: "waf.rate_limit_rpm",    value: JSON.stringify(300),   category: "thresholds",   description: "Global rate limit per IP (requests per minute)" },
      { key: "waf.block_duration_min",value: JSON.stringify(60),    category: "thresholds",   description: "Auto-block duration in minutes (0 = permanent)" },
      { key: "waf.sensitivity",       value: JSON.stringify("medium"), category: "thresholds", description: "Overall WAF sensitivity: low | medium | high | paranoid" },
      // Whitelisted IPs / CIDRs
      { key: "waf.whitelist_ips",     value: JSON.stringify(["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"]), category: "whitelist", description: "IPs and CIDRs that bypass WAF inspection" },
      // Alert destinations
      { key: "alerts.email_enabled",  value: JSON.stringify(false), category: "alerts", description: "Send email alerts for critical events" },
      { key: "alerts.email_to",       value: JSON.stringify("soc@company.com"), category: "alerts", description: "Comma-separated list of alert email recipients" },
      { key: "alerts.webhook_enabled",value: JSON.stringify(false), category: "alerts", description: "Send webhook POST on critical events" },
      { key: "alerts.webhook_url",    value: JSON.stringify(""),    category: "alerts", description: "Webhook endpoint URL" },
      { key: "alerts.severity_min",   value: JSON.stringify("high"), category: "alerts", description: "Minimum severity to trigger alerts: low | medium | high | critical" },
      // Integration keys
      { key: "integrations.siem_url",       value: JSON.stringify(""), category: "integrations", description: "SIEM ingestion endpoint (e.g. Splunk HEC URL)" },
      { key: "integrations.siem_token",     value: JSON.stringify(""), category: "integrations", description: "SIEM API token / HEC token" },
      { key: "integrations.slack_webhook",  value: JSON.stringify(""), category: "integrations", description: "Slack incoming webhook URL for #soc-alerts" },
      { key: "integrations.pagerduty_key",  value: JSON.stringify(""), category: "integrations", description: "PagerDuty Events API v2 integration key" },
      // Reports
      { key: "reports.schedule_enabled", value: JSON.stringify(false),  category: "reports", description: "Enable scheduled automated report delivery" },
      { key: "reports.schedule_cron",    value: JSON.stringify("0 8 * * 1"), category: "reports", description: "Cron expression for scheduled reports (default: Mon 08:00)" },
      { key: "reports.schedule_email",   value: JSON.stringify("management@company.com"), category: "reports", description: "Recipients for scheduled reports" },
      { key: "reports.schedule_type",    value: JSON.stringify("weekly"), category: "reports", description: "Default scheduled report type: daily | weekly | threats | ips | trends" },
    ];

    for (const s of defaults) {
      await db.pool.query(
        `INSERT INTO soc_settings (key, value, description, category) VALUES ($1, $2::jsonb, $3, $4) ON CONFLICT DO NOTHING`,
        [s.key, s.value, s.description, s.category]
      );
    }
    console.log("⚙️  System settings seeded with defaults");
  }
}

ensureSettingsTable().catch(console.error);

// ── Auth middleware (JWT verify, admin-only) ────────────────────────────────────
function requireAdmin(req, res, next) {
  let jwt;
  try { jwt = require("jsonwebtoken"); } catch { return res.status(503).json({ error: "JWT not installed" }); }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });

  try {
    const payload = jwt.verify(authHeader.slice(7), process.env.JWT_SECRET || "soc-dashboard-super-secret-key-change-in-prod");
    if (payload.role !== "admin") return res.status(403).json({ error: "Admin access required" });
    req.authUser = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ── GET /api/settings ─────────────────────────────────────────────────────────
router.get("/", requireAdmin, async (req, res) => {
  try {
    const { category } = req.query;
    const where  = category ? "WHERE category = $1" : "";
    const params = category ? [category] : [];
    const { rows } = await db.pool.query(
      `SELECT key, value, description, category, updated_at, updated_by FROM soc_settings ${where} ORDER BY category, key`,
      params
    );
    // Group by category for convenience
    const grouped = {};
    for (const row of rows) {
      if (!grouped[row.category]) grouped[row.category] = {};
      grouped[row.category][row.key] = { value: row.value, description: row.description, updated_at: row.updated_at, updated_by: row.updated_by };
    }
    res.json({ settings: grouped, flat: rows });
  } catch (err) {
    console.error("Settings fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// ── PATCH /api/settings ───────────────────────────────────────────────────────
// Body: { updates: { "waf.block_threshold": 10, ... } }
router.patch("/", requireAdmin, async (req, res) => {
  const { updates } = req.body;
  if (!updates || typeof updates !== "object") return res.status(400).json({ error: "updates object required" });

  const updatedBy = req.authUser?.username || "admin";

  try {
    const keys    = Object.keys(updates);
    const results = [];
    for (const key of keys) {
      const val = updates[key];
      const { rows } = await db.pool.query(
        `UPDATE soc_settings
         SET value = $1::jsonb, updated_at = NOW(), updated_by = $2
         WHERE key = $3
         RETURNING key, value, category, updated_at`,
        [JSON.stringify(val), updatedBy, key]
      );
      if (rows[0]) results.push(rows[0]);
    }
    res.json({ updated: results.length, results });
    // Immediately re-read WAF settings into the live config cache
    await wafConfig.refreshFromDb();
    // If the whitelist was updated, immediately unblock any affected IPs
    if (updates["waf.whitelist_ips"] && Array.isArray(updates["waf.whitelist_ips"])) {
      for (const ip of updates["waf.whitelist_ips"]) {
        if (store.blockedIPs.has(ip)) {
          store.blockedIPs.delete(ip);
          db.pool.query(
            "UPDATE waf_blocked_ips SET unblocked_at = NOW() WHERE ip_address = $1 AND unblocked_at IS NULL",
            [ip]
          ).catch(() => {});
        }
      }
    }
    // Fire audit log after responding
    writeAuditLog({
      userId: req.authUser?.id, username: updatedBy, role: req.authUser?.role,
      action: "settings_updated", category: "settings",
      target: keys.join(", "), detail: updates, ipAddress: req.ip, outcome: "success",
    }).catch(() => {});
  } catch (err) {
    console.error("Settings update error:", err.message);
    res.status(500).json({ error: "Failed to update settings" });
  }
});

// ── PUT /api/settings/whitelist ────────────────────────────────────────────────
router.put("/whitelist", requireAdmin, async (req, res) => {
  const { ips } = req.body; // array of strings
  if (!Array.isArray(ips)) return res.status(400).json({ error: "ips must be an array" });

  try {
    await db.pool.query(
      `UPDATE soc_settings SET value = $1::jsonb, updated_at = NOW(), updated_by = $2 WHERE key = 'waf.whitelist_ips'`,
      [JSON.stringify(ips), req.authUser?.username || "admin"]
    );

    // Immediately refresh the live WAF cache so new whitelist entries take effect now
    await wafConfig.refreshFromDb();

    // Unblock any currently-blocked IPs that are now whitelisted
    // so their next request is shown as "allowed" rather than "blocked"
    for (const ip of ips) {
      if (store.blockedIPs.has(ip)) {
        store.blockedIPs.delete(ip);
        db.pool.query(
          "UPDATE waf_blocked_ips SET unblocked_at = NOW() WHERE ip_address = $1 AND unblocked_at IS NULL",
          [ip]
        ).catch(() => {});
        console.log(`🟢  Whitelist: unblocked ${ip}`);
      }
    }

    writeAuditLog({
      userId: req.authUser?.id, username: req.authUser?.username || "admin",
      role: req.authUser?.role,
      action: "whitelist_updated", category: "settings",
      target: "waf.whitelist_ips", detail: { ips },
      ipAddress: req.ip, outcome: "success",
    }).catch(() => {});

    res.json({ success: true, ips });
  } catch (err) {
    res.status(500).json({ error: "Failed to update whitelist" });
  }
});

module.exports = router;
