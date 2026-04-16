/**
 * wafConfig.js — Live WAF configuration cache
 *
 * Reads settings from `soc_settings` (written by System Settings page) and
 * exposes them to wafMiddleware. Refreshes every 30 seconds so changes made
 * in the UI take effect quickly without a server restart.
 *
 * Keys consumed:
 *   waf.block_threshold    — how many rule hits before auto-block          (default 5)
 *   waf.log_threshold      — hits before switching from log to monitor     (default 2)
 *   waf.rate_limit_rpm     — global req/min cap per IP                     (default 300)
 *   waf.block_duration_min — how long auto-blocks last (0 = permanent)     (default 60)
 *   waf.sensitivity        — "low"|"medium"|"high"|"paranoid"              (default "medium")
 *   waf.whitelist_ips      — array of IP strings / CIDRs                  (default [])
 */

const db = require("./database");

// ── Defaults (used until DB is reachable) ────────────────────────────────────

const DEFAULTS = {
  blockThreshold:  5,
  logThreshold:    2,
  rateLimitRpm:    300,
  blockDurationMin: 60,
  sensitivity:     "medium",
  whitelistIps:    [],
};

// Sensitivity → multiplier applied on top of per-rule thresholds
// "low"     → rules need 3× more hits before triggering
// "medium"  → rules behave exactly as configured
// "high"    → rules trigger at 50% of their configured threshold
// "paranoid"→ rules trigger at 25% of their configured threshold (min 1)
const SENSITIVITY_MULTIPLIER = {
  low:      3.0,
  medium:   1.0,
  high:     0.5,
  paranoid: 0.25,
};

// ── Live config object (mutated in-place so existing references stay valid) ──

const config = { ...DEFAULTS };

// ── CIDR helpers ─────────────────────────────────────────────────────────────

function ipToLong(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function ipInCidr(ip, cidr) {
  if (!cidr.includes("/")) return ip === cidr;
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - parseInt(bits))) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
}

/**
 * Returns true if the given IP is in the admin-managed whitelist.
 */
function isWhitelistedBySettings(ip) {
  if (!ip) return false;
  const clean = ip.replace("::ffff:", "").replace("::1", "127.0.0.1");
  return config.whitelistIps.some(entry => {
    try { return ipInCidr(clean, entry); } catch { return clean === entry; }
  });
}

/**
 * Apply sensitivity multiplier to a raw rule threshold.
 * Always returns at least 1.
 */
function applyThreshold(rawThreshold) {
  const multiplier = SENSITIVITY_MULTIPLIER[config.sensitivity] ?? 1.0;
  return Math.max(1, Math.round(rawThreshold * multiplier));
}

/**
 * Returns the effective global block threshold (used when no per-rule threshold exists).
 */
function getBlockThreshold() {
  return applyThreshold(config.blockThreshold);
}

/**
 * Returns the effective rate-limit (req/min) for the current sensitivity.
 */
function getRateLimitRpm() {
  return applyThreshold(config.rateLimitRpm);
}

// ── DB refresh ───────────────────────────────────────────────────────────────

async function refreshFromDb() {
  try {
    const { rows } = await db.pool.query(
      `SELECT key, value FROM soc_settings WHERE key LIKE 'waf.%'`
    );

    for (const row of rows) {
      const val = row.value; // already parsed by pg JSONB driver
      switch (row.key) {
        case "waf.block_threshold":    config.blockThreshold    = Number(val)  || DEFAULTS.blockThreshold;   break;
        case "waf.log_threshold":      config.logThreshold      = Number(val)  || DEFAULTS.logThreshold;     break;
        case "waf.rate_limit_rpm":     config.rateLimitRpm      = Number(val)  || DEFAULTS.rateLimitRpm;     break;
        case "waf.block_duration_min": config.blockDurationMin  = Number(val);                               break;
        case "waf.sensitivity":        config.sensitivity       = String(val)  || DEFAULTS.sensitivity;      break;
        case "waf.whitelist_ips":      config.whitelistIps      = Array.isArray(val) ? val : DEFAULTS.whitelistIps; break;
      }
    }
  } catch {
    // DB not ready yet — keep using current (default) values
  }
}

// Refresh immediately on startup, then every 30 s
refreshFromDb();
const _interval = setInterval(refreshFromDb, 30_000);
// Don't hold the process open just for this
if (_interval.unref) _interval.unref();

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  config,               // raw live config object (read-only — do not mutate externally)
  isWhitelistedBySettings,
  applyThreshold,
  getBlockThreshold,
  getRateLimitRpm,
  refreshFromDb,        // callable manually (e.g. after a settings PATCH)
};
