/**
 * Incident Engine
 * Periodically scans recent WAF alerts and auto-creates/updates
 * incidents by grouping correlated attack events.
 */

const db = require("./database");

const SEVERITY_MAP = {
  SQLi: "critical",
  RCE: "critical",
  XSS: "high",
  DDoS: "high",
  "Path Traversal": "high",
  "Brute Force": "medium",
  CSRF: "medium",
  Other: "low",
};

const INCIDENT_TITLES = {
  SQLi: "SQL Injection Campaign Detected",
  XSS: "Cross-Site Scripting Attack Wave",
  "Brute Force": "Brute Force Attack on Authentication",
  DDoS: "DDoS Traffic Spike Detected",
  "Path Traversal": "Directory Traversal Attempts",
  RCE: "Remote Code Execution Attempt",
  CSRF: "Cross-Site Request Forgery Activity",
  Other: "Suspicious Activity Detected",
};

// Minimum alerts in a window to form an incident
const INCIDENT_THRESHOLD = 5;
// Look back window in minutes
const LOOKBACK_MINUTES = 60;

async function runIncidentEngine() {
  try {
    const since = new Date(Date.now() - LOOKBACK_MINUTES * 60 * 1000);

    // Fetch recent alerts from DB
    const result = await db.pool.query(
      `SELECT id, attack_type, source_ip, target_url, severity, action, timestamp
       FROM waf_alerts
       WHERE timestamp >= $1
       ORDER BY timestamp DESC`,
      [since]
    );

    const alerts = result.rows;
    if (alerts.length === 0) return;

    // Group alerts by attack type
    const groups = {};
    for (const alert of alerts) {
      const type = alert.attack_type || "Other";
      if (!groups[type]) groups[type] = [];
      groups[type].push(alert);
    }

    for (const [attackType, typeAlerts] of Object.entries(groups)) {
      if (typeAlerts.length < INCIDENT_THRESHOLD) continue;

      // Collect unique IPs and endpoints
      const relatedIPs = [...new Set(typeAlerts.map((a) => a.source_ip))].slice(0, 20);
      const affectedEndpoints = [...new Set(typeAlerts.map((a) => a.target_url))].slice(0, 10);
      const timestamps = typeAlerts.map((a) => new Date(a.timestamp)).sort((a, b) => a - b);
      const startTime = timestamps[0];
      const endTime = timestamps[timestamps.length - 1];
      const severity = SEVERITY_MAP[attackType] || "medium";
      const blockedCount = typeAlerts.filter((a) => a.action === "blocked").length;

      // Build a stable incident ID based on attack type + day (one per day per type)
      const dayStr = startTime.toISOString().slice(0, 10).replace(/-/g, "");
      const incidentId = `INC-${attackType.replace(/\s+/g, "").toUpperCase().slice(0, 6)}-${dayStr}`;

      const notes =
        `${typeAlerts.length} ${attackType} events detected from ${relatedIPs.length} unique IP(s). ` +
        `${blockedCount} requests blocked. ` +
        `Targeting: ${affectedEndpoints.slice(0, 3).join(", ")}${affectedEndpoints.length > 3 ? "..." : ""}.`;

      // Check if incident already exists
      const existing = await db.getIncidentById(incidentId);

      if (existing) {
        // BUG FIX: compare serialised IPs so we detect new unique IPs joining,
        // not just a change in raw event count.
        const existingIPsSorted  = [...(existing.relatedIPs || [])].sort().join(",");
        const freshIPsSorted     = [...relatedIPs].sort().join(",");
        const ipSetChanged       = existingIPsSorted !== freshIPsSorted;
        const countChanged       = existing.eventCount !== typeAlerts.length;

        if (ipSetChanged || countChanged) {
          // Preserve the analyst's status — only update data fields
          await db.pool.query(
            `UPDATE waf_incidents
             SET event_count=$1, related_ips=$2, affected_endpoints=$3,
                 end_time=$4, notes=$5, updated_at=NOW()
             WHERE id=$6`,
            [typeAlerts.length, relatedIPs, affectedEndpoints, endTime, notes, incidentId]
          );
          console.log(
            `🔄 Incident updated: ${incidentId} — ${attackType} ` +
            `(${typeAlerts.length} events, ${relatedIPs.length} IPs)`
          );
        }
      } else {
        // Create new incident
        await db.upsertIncident({
          id: incidentId,
          title: INCIDENT_TITLES[attackType] || `${attackType} Attack Detected`,
          timeRange: { start: startTime, end: endTime },
          severity,
          status: severity === "critical" ? "open" : severity === "high" ? "investigating" : "open",
          eventCount: typeAlerts.length,
          affectedEndpoints,
          relatedIPs,
          assignee: severity === "critical" || severity === "high" ? "Security Team" : null,
          notes,
        });
        console.log(`🚨 Incident created: ${incidentId} — ${attackType} (${typeAlerts.length} events, ${relatedIPs.length} IPs)`);
      }
    }
  } catch (err) {
    console.error("Incident engine error:", err.message);
  }
}

/**
 * Seeds initial incidents from existing alerts on first boot.
 * BUG FIX: The old guard (count > 0) meant that once any incident existed,
 * seeding was permanently skipped — so 100+ new IPs were never reflected.
 * Now we always run the engine on boot so it can update existing incidents
 * with fresh IPs/counts, without touching analyst status fields.
 */
async function seedIncidentsFromAlerts() {
  try {
    console.log("🔄  Running incident engine on boot (create new + refresh existing)...");
    await runIncidentEngine();
    const count = await db.pool.query("SELECT COUNT(*) FROM waf_incidents");
    console.log(`✅  Incident engine boot run complete — ${count.rows[0].count} incident(s) in DB.`);
  } catch (err) {
    console.error("Failed to seed incidents:", err.message);
  }
}

/**
 * Start the incident engine — runs once immediately, then every 60 seconds.
 */
function startIncidentEngine() {
  console.log("🛡️  Incident engine started (runs every 60s)");
  runIncidentEngine(); // run immediately on boot
  return setInterval(runIncidentEngine, 60 * 1000);
}

module.exports = { startIncidentEngine, seedIncidentsFromAlerts, runIncidentEngine };

