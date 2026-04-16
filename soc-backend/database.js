/**
 * PostgreSQL Database Layer — WAF SOC Dashboard
 * All DB queries are centralized here. Other files just call these functions.
 */

const { Pool } = require("pg");

// ─── Connection Pool ──────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  host:     process.env.DB_HOST     || "localhost",
  port:     parseInt(process.env.DB_PORT || "5432"),
  database: process.env.DB_NAME     || "waf_dashboard",
  user:     process.env.DB_USER     || "postgres",
  password: process.env.DB_PASSWORD || "",
  max: 40,                        // increased from 20 — handles burst load from simulator
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,  // increased from 2000 — gives dashboard routes a chance during spikes
});

pool.on("error", (err) => {
  console.error("PostgreSQL pool error:", err.message);
});

// ─── Schema ───────────────────────────────────────────────────────────────────
const SCHEMA_SQL = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS waf_alerts (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attack_type         VARCHAR(50)  NOT NULL,
  source_ip           VARCHAR(45)  NOT NULL,
  target_url          TEXT,
  severity            VARCHAR(20)  CHECK (severity IN ('critical','high','medium','low','info')),
  action              VARCHAR(20)  CHECK (action IN ('blocked','allowed')),
  country             VARCHAR(100),
  country_code        CHAR(2),
  request_method      VARCHAR(10),
  user_agent          TEXT,
  payload             TEXT,
  rule_id             VARCHAR(100),
  rule_name           VARCHAR(200),
  matched_sids        TEXT,
  snort_msg           TEXT,
  false_positive_score INTEGER DEFAULT 0,
  cve_reference       VARCHAR(50),
  device_os           VARCHAR(100),
  device_browser      VARCHAR(200),
  device_type         VARCHAR(50),
  is_malicious_tool   BOOLEAN DEFAULT FALSE,
  tool_name           VARCHAR(200),
  device_fingerprint  VARCHAR(16),
  forwarded_for       VARCHAR(45),
  protocol            VARCHAR(10),
  http_version        VARCHAR(10),
  request_size        INTEGER DEFAULT 0,
  content_type        VARCHAR(200),
  referer             TEXT,
  accept_language     VARCHAR(200)
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp    ON waf_alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip    ON waf_alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type  ON waf_alerts (attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON waf_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_action       ON waf_alerts (action);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint  ON waf_alerts (device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_country      ON waf_alerts (country_code);
ALTER TABLE waf_alerts ADD COLUMN IF NOT EXISTS latitude  DOUBLE PRECISION;
ALTER TABLE waf_alerts ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS idx_alerts_geo ON waf_alerts (latitude, longitude) WHERE latitude IS NOT NULL;

CREATE TABLE IF NOT EXISTS waf_incidents (
  id                  VARCHAR(20)  PRIMARY KEY,
  title               VARCHAR(500) NOT NULL,
  start_time          TIMESTAMPTZ  NOT NULL,
  end_time            TIMESTAMPTZ,
  severity            VARCHAR(20),
  status              VARCHAR(30)  CHECK (status IN ('open','investigating','resolved','closed')) DEFAULT 'open',
  event_count         INTEGER      DEFAULT 0,
  affected_endpoints  TEXT[],
  related_ips         TEXT[],
  assignee            VARCHAR(200),
  notes               TEXT,
  created_at          TIMESTAMPTZ  DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_rules (
  id          VARCHAR(100) PRIMARY KEY,
  name        VARCHAR(300) NOT NULL,
  category    VARCHAR(50)  NOT NULL,
  description TEXT,
  enabled     BOOLEAN      DEFAULT TRUE,
  threshold   INTEGER      DEFAULT 1,
  severity    VARCHAR(20),
  action      VARCHAR(20)  CHECK (action IN ('blocked','allowed','log')) DEFAULT 'blocked',
  created_at  TIMESTAMPTZ  DEFAULT NOW(),
  updated_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_blocked_ips (
  ip          VARCHAR(45)  PRIMARY KEY,
  blocked_at  TIMESTAMPTZ  DEFAULT NOW(),
  reason      VARCHAR(200),
  blocked_by  VARCHAR(100) DEFAULT 'auto',
  expires_at  TIMESTAMPTZ,
  attack_count INTEGER DEFAULT 1
);
`;

// ─── Init ─────────────────────────────────────────────────────────────────────
async function initDatabase(seedRules) {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA_SQL);

    // Seed WAF rules if table is empty
    if (seedRules && seedRules.length > 0) {
      const existing = await client.query("SELECT COUNT(*) FROM waf_rules");
      if (parseInt(existing.rows[0].count) === 0) {
        for (const rule of seedRules) {
          await client.query(
            `INSERT INTO waf_rules (id, name, category, description, enabled, threshold, severity, action, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
            [rule.id, rule.name, rule.category, rule.description, rule.enabled,
             rule.threshold, rule.severity, rule.action, rule.createdAt, rule.updatedAt]
          );
        }
        console.log(`✅  PostgreSQL: Seeded ${seedRules.length} WAF rules`);
      }
    }

    // Load blocked IPs into memory Set for fast WAF checks
    const blockedResult = await client.query(
      "SELECT ip FROM waf_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()"
    );
    console.log(`✅  PostgreSQL: Schema ready — loaded ${blockedResult.rows.length} blocked IPs`);
    return blockedResult.rows.map(r => r.ip);
  } finally {
    client.release();
  }
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
// ─── Alert Write Buffer ───────────────────────────────────────────────────────
// Instead of one pool.query() per alert (which exhausts connections under
// simulator load), we buffer alerts and flush them in a single multi-row
// INSERT every 500ms. This collapses ~30 individual queries/sec into 1-2.
const _alertBuffer   = [];
let   _alertFlushTimer = null;
const ALERT_FLUSH_INTERVAL_MS = 500;
const ALERT_COLS = [
  "id","timestamp","attack_type","source_ip","target_url","severity","action",
  "country","country_code","request_method","user_agent","payload",
  "rule_id","rule_name","matched_sids","snort_msg","false_positive_score","cve_reference",
  "device_os","device_browser","device_type","is_malicious_tool","tool_name","device_fingerprint",
  "forwarded_for","protocol","http_version","request_size","content_type","referer",
  "accept_language","latitude","longitude",
];
const NUM_COLS = ALERT_COLS.length; // 33

function _alertToValues(a) {
  return [
    a.id, a.timestamp, a.attackType, a.sourceIP, a.targetURL,
    a.severity, a.action, a.country, a.countryCode, a.requestMethod,
    a.userAgent, a.payload ?? null, a.ruleId ?? null, a.ruleName ?? null,
    a.matchedSIDs ?? null, a.snortMsg ?? null, a.falsePositiveScore || 0, a.cveReference ?? null,
    a.device?.os ?? null, a.device?.browser ?? null, a.device?.deviceType ?? null,
    a.device?.isMaliciousTool || false, a.device?.toolName ?? null, a.device?.fingerprint ?? null,
    a.network?.forwardedFor ?? null, a.network?.protocol ?? null, a.network?.httpVersion ?? null,
    a.requestSize || 0, a.contentType ?? null, a.referer ?? null, a.acceptLanguage ?? null,
    a.latitude ?? null, a.longitude ?? null,
  ];
}

async function _flushAlerts() {
  _alertFlushTimer = null;
  if (_alertBuffer.length === 0) return;
  const batch = _alertBuffer.splice(0); // drain the buffer atomically

  const values      = [];
  const rowClauses  = batch.map((alert, i) => {
    const vals = _alertToValues(alert);
    values.push(...vals);
    const placeholders = vals.map((_, k) => `$${i * NUM_COLS + k + 1}`).join(",");
    return `(${placeholders})`;
  });

  const sql = `
    INSERT INTO waf_alerts (${ALERT_COLS.join(",")})
    VALUES ${rowClauses.join(",")}
    ON CONFLICT (id) DO NOTHING
  `;

  try {
    await pool.query(sql, values);
  } catch (err) {
    console.error(`Batch alert insert failed (${batch.length} rows):`, err.message);
  }
}

function insertAlert(alert) {
  // Push into the buffer — the timer will flush it shortly.
  // Returns a resolved promise so callers can still do .catch() on it.
  _alertBuffer.push(alert);
  if (!_alertFlushTimer) {
    _alertFlushTimer = setTimeout(_flushAlerts, ALERT_FLUSH_INTERVAL_MS);
  }
  return Promise.resolve();
}

async function getAlerts({ ip, severity, attackType, action, from, to, page = 1, limit = 100 } = {}) {
  const conditions = ["1=1"];
  const values = [];
  let i = 1;

  if (ip)         { conditions.push(`source_ip ILIKE $${i++}`);  values.push(`%${ip}%`); }
  if (severity && severity !== "all") { conditions.push(`severity = $${i++}`);    values.push(severity); }
  if (attackType && attackType !== "all") { conditions.push(`attack_type = $${i++}`); values.push(attackType); }
  if (action && action !== "all")     { conditions.push(`action = $${i++}`);      values.push(action); }
  if (from)       { conditions.push(`timestamp >= $${i++}`);     values.push(new Date(from)); }
  if (to)         { conditions.push(`timestamp <= $${i++}`);     values.push(new Date(to)); }

  const countResult = await pool.query(
    `SELECT COUNT(*) FROM waf_alerts WHERE ${conditions.join(" AND ")}`, values
  );
  const total = parseInt(countResult.rows[0].count);

  const offset = (parseInt(page) - 1) * parseInt(limit);
  values.push(parseInt(limit), offset);

  const dataResult = await pool.query(
    `SELECT * FROM waf_alerts WHERE ${conditions.join(" AND ")}
     ORDER BY timestamp DESC LIMIT $${i++} OFFSET $${i++}`,
    values
  );

  return { rows: dataResult.rows.map(dbRowToAlert), total };
}

async function getAlertById(id) {
  const result = await pool.query("SELECT * FROM waf_alerts WHERE id = $1", [id]);
  return result.rows[0] ? dbRowToAlert(result.rows[0]) : null;
}

async function getAlertsByIP(ip, limit = 50) {
  const result = await pool.query(
    "SELECT * FROM waf_alerts WHERE source_ip = $1 ORDER BY timestamp DESC LIMIT $2",
    [ip, limit]
  );
  return result.rows.map(dbRowToAlert);
}

async function getLiveAlerts(limit = 20) {
  const result = await pool.query(
    "SELECT * FROM waf_alerts ORDER BY timestamp DESC LIMIT $1", [limit]
  );
  return result.rows.map(dbRowToAlert);
}

// ─── Dashboard Stats ──────────────────────────────────────────────────────────
async function getDashboardStats() {
  const now = new Date();
  const h24 = new Date(now - 24 * 60 * 60 * 1000);

  const [totals, topAttackTypes, topCountries, requestsOverTime, severityDist, topIPs] = await Promise.all([
    pool.query(`
      SELECT
        COUNT(*)                                         AS total_requests,
        COUNT(*) FILTER (WHERE action = 'blocked')       AS blocked_requests,
        COUNT(DISTINCT source_ip)                        AS unique_attackers
      FROM waf_alerts WHERE timestamp >= $1`, [h24]),

    pool.query(`
      SELECT attack_type AS type, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp >= $1
      GROUP BY attack_type ORDER BY count DESC LIMIT 10`, [h24]),

    pool.query(`
      SELECT country, country_code, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp >= $1
      GROUP BY country, country_code ORDER BY count DESC LIMIT 10`, [h24]),

    pool.query(`
      SELECT
        date_trunc('hour', timestamp) AS hour,
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE action = 'blocked') AS blocked
      FROM waf_alerts
      WHERE timestamp >= $1
      GROUP BY date_trunc('hour', timestamp)
      ORDER BY hour`, [h24]),

    pool.query(`
      SELECT severity, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp >= $1
      GROUP BY severity`, [h24]),

    pool.query(`
      SELECT source_ip AS ip, country, country_code,
             COUNT(*) AS count,
             COUNT(*) FILTER (WHERE action='blocked') AS blocked,
             ARRAY_AGG(DISTINCT attack_type) AS attack_types
      FROM waf_alerts WHERE timestamp >= $1
      GROUP BY source_ip, country, country_code
      ORDER BY count DESC LIMIT 5`, [h24]),
  ]);

  const t = totals.rows[0];

  // Format hourly data into 24 slots
  const hourSlots = [];
  for (let i = 23; i >= 0; i--) {
    const slotTime = new Date(now.getTime() - i * 60 * 60 * 1000);
    const slotHour = new Date(slotTime);
    slotHour.setMinutes(0, 0, 0);
    const match = requestsOverTime.rows.find(
      r => new Date(r.hour).getTime() === slotHour.getTime()
    );
    hourSlots.push({
      time: slotTime.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
      total: match ? parseInt(match.total) : 0,
      blocked: match ? parseInt(match.blocked) : 0,
    });
  }

  return {
    totalRequests:    parseInt(t.total_requests),
    blockedRequests:  parseInt(t.blocked_requests),
    uniqueAttackers:  parseInt(t.unique_attackers),
    topAttackTypes:   topAttackTypes.rows.map(r => ({ type: r.type, count: parseInt(r.count) })),
    topCountries:     topCountries.rows.map(r => ({ country: r.country, countryCode: r.country_code, count: parseInt(r.count) })),
    requestsOverTime: hourSlots,
    severityDistribution: severityDist.rows.map(r => ({ severity: r.severity, count: parseInt(r.count) })),
    topAttackingIPs: topIPs.rows.map(r => ({
      ip: r.ip,
      country: r.country,
      countryCode: r.country_code,
      count: parseInt(r.count),
      blockedRequests: parseInt(r.blocked),
      attackTypes: r.attack_types || [],
      riskScore: Math.min(Math.round((parseInt(r.blocked) / Math.max(parseInt(r.count), 1)) * 100), 99),
    })),
  };
}

// ─── Analytics ────────────────────────────────────────────────────────────────
async function getAnalytics(from, to) {
  const fromDate = from ? new Date(from) : new Date(Date.now() - 24 * 60 * 60 * 1000);
  const toDate   = to   ? new Date(to)   : new Date();

  const [topURLs, topIPs, attackBreakdown, severityDist, methodDist, hourlyData] = await Promise.all([
    pool.query(`
      SELECT target_url AS url, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY target_url ORDER BY count DESC LIMIT 8`, [fromDate, toDate]),

    pool.query(`
      SELECT source_ip AS ip, country, country_code,
             COUNT(*) AS count,
             COUNT(*) FILTER (WHERE action='blocked') AS blocked,
             ARRAY_AGG(DISTINCT attack_type) AS attack_types
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY source_ip, country, country_code
      ORDER BY count DESC LIMIT 10`, [fromDate, toDate]),

    pool.query(`
      SELECT attack_type AS type,
             COUNT(*) AS count,
             COUNT(*) FILTER (WHERE action='blocked') AS blocked
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY attack_type ORDER BY count DESC`, [fromDate, toDate]),

    pool.query(`
      SELECT severity, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY severity`, [fromDate, toDate]),

    pool.query(`
      SELECT request_method AS method, COUNT(*) AS count
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY request_method`, [fromDate, toDate]),

    pool.query(`
      SELECT date_trunc('hour', timestamp) AS hour,
             COUNT(*) AS attacks,
             COUNT(*) FILTER (WHERE action='blocked') AS blocked
      FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2
      GROUP BY date_trunc('hour', timestamp)
      ORDER BY hour`, [fromDate, toDate]),
  ]);

  return {
    topURLs:            topURLs.rows.map(r => ({ url: r.url, count: parseInt(r.count) })),
    topAttackingIPs:    topIPs.rows.map(r => ({ ip: r.ip, country: r.country, countryCode: r.country_code, count: parseInt(r.count), blocked: parseInt(r.blocked), attackTypes: r.attack_types, riskScore: Math.min(Math.floor((parseInt(r.blocked) / Math.max(parseInt(r.count), 1)) * 100), 99) })),
    attackTypeBreakdown: attackBreakdown.rows.map(r => ({ type: r.type, count: parseInt(r.count), blocked: parseInt(r.blocked) })),
    severityDistribution: severityDist.rows.map(r => ({ severity: r.severity, count: parseInt(r.count) })),
    methodDistribution:  methodDist.rows.map(r => ({ method: r.method, count: parseInt(r.count) })),
    hourlyData:          hourlyData.rows.map(r => ({ hour: new Date(r.hour).getHours() + ":00", attacks: parseInt(r.attacks), blocked: parseInt(r.blocked) })),
    totalAnalyzed:       (await pool.query("SELECT COUNT(*) FROM waf_alerts WHERE timestamp BETWEEN $1 AND $2", [fromDate, toDate])).rows[0].count,
  };
}

// ─── Incidents ────────────────────────────────────────────────────────────────
async function getIncidents({ status, severity } = {}) {
  const conditions = ["1=1"];
  const values = [];
  let i = 1;
  if (status && status !== "all")   { conditions.push(`status = $${i++}`);   values.push(status); }
  if (severity && severity !== "all") { conditions.push(`severity = $${i++}`); values.push(severity); }

  const result = await pool.query(
    `SELECT * FROM waf_incidents WHERE ${conditions.join(" AND ")} ORDER BY start_time DESC`,
    values
  );
  return result.rows.map(dbRowToIncident);
}

async function getIncidentById(id) {
  const result = await pool.query("SELECT * FROM waf_incidents WHERE id = $1", [id]);
  return result.rows[0] ? dbRowToIncident(result.rows[0]) : null;
}

async function upsertIncident(incident) {
  await pool.query(`
    INSERT INTO waf_incidents (id, title, start_time, end_time, severity, status, event_count, affected_endpoints, related_ips, assignee, notes, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
    ON CONFLICT (id) DO UPDATE SET
      title=EXCLUDED.title, status=EXCLUDED.status, assignee=EXCLUDED.assignee,
      notes=EXCLUDED.notes, event_count=EXCLUDED.event_count, updated_at=NOW()`,
    [incident.id, incident.title, incident.timeRange?.start || new Date(), incident.timeRange?.end,
     incident.severity, incident.status, incident.eventCount || 0,
     incident.affectedEndpoints || [], incident.relatedIPs || [],
     incident.assignee, incident.notes]
  );
}

async function updateIncident(id, updates) {
  const fields = [];
  const values = [];
  let i = 1;
  if (updates.status   !== undefined) { fields.push(`status=$${i++}`);   values.push(updates.status); }
  if (updates.assignee !== undefined) { fields.push(`assignee=$${i++}`); values.push(updates.assignee); }
  if (updates.notes    !== undefined) { fields.push(`notes=$${i++}`);    values.push(updates.notes); }
  fields.push(`updated_at=NOW()`);
  values.push(id);
  const result = await pool.query(
    `UPDATE waf_incidents SET ${fields.join(",")} WHERE id=$${i} RETURNING *`, values
  );
  return result.rows[0] ? dbRowToIncident(result.rows[0]) : null;
}

// ─── Rules ────────────────────────────────────────────────────────────────────
async function getRules() {
  const result = await pool.query("SELECT * FROM waf_rules ORDER BY created_at");
  return result.rows.map(dbRowToRule);
}

async function getRuleById(id) {
  const result = await pool.query("SELECT * FROM waf_rules WHERE id=$1", [id]);
  return result.rows[0] ? dbRowToRule(result.rows[0]) : null;
}

async function updateRule(id, updates) {
  const fields = [];
  const values = [];
  let i = 1;
  if (updates.enabled   !== undefined) { fields.push(`enabled=$${i++}`);   values.push(updates.enabled); }
  if (updates.threshold !== undefined) { fields.push(`threshold=$${i++}`); values.push(updates.threshold); }
  if (updates.action    !== undefined) { fields.push(`action=$${i++}`);    values.push(updates.action); }
  if (updates.severity  !== undefined) { fields.push(`severity=$${i++}`);  values.push(updates.severity); }
  fields.push(`updated_at=NOW()`);
  values.push(id);
  const result = await pool.query(
    `UPDATE waf_rules SET ${fields.join(",")} WHERE id=$${i} RETURNING *`, values
  );
  return result.rows[0] ? dbRowToRule(result.rows[0]) : null;
}

async function createRule(rule) {
  const result = await pool.query(`
    INSERT INTO waf_rules (id, name, category, description, enabled, threshold, severity, action)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [rule.id, rule.name, rule.category, rule.description || "",
     rule.enabled ?? false, rule.threshold || 1, rule.severity || "medium", rule.action || "blocked"]
  );
  return dbRowToRule(result.rows[0]);
}

async function deleteRule(id) {
  const result = await pool.query("DELETE FROM waf_rules WHERE id=$1 RETURNING *", [id]);
  return result.rows[0] ? dbRowToRule(result.rows[0]) : null;
}

// ─── Blocked IPs ──────────────────────────────────────────────────────────────
async function blockIP(ip, reason = "WAF auto-block", blockedBy = "auto") {
  await pool.query(`
    INSERT INTO waf_blocked_ips (ip, reason, blocked_by)
    VALUES ($1,$2,$3)
    ON CONFLICT (ip) DO UPDATE SET attack_count = waf_blocked_ips.attack_count + 1, reason=EXCLUDED.reason`,
    [ip, reason, blockedBy]
  );
}

async function unblockIP(ip) {
  await pool.query("DELETE FROM waf_blocked_ips WHERE ip=$1", [ip]);
}

async function getBlockedIPs() {
  const result = await pool.query(
    "SELECT ip FROM waf_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()"
  );
  return result.rows.map(r => r.ip);
}

// ─── IP Intelligence ──────────────────────────────────────────────────────────
async function getIPActivity(ip) {
  const result = await pool.query(`
    SELECT
      COUNT(*)                                         AS total,
      COUNT(*) FILTER (WHERE action='blocked')         AS blocked,
      MIN(timestamp)                                   AS first_seen,
      MAX(timestamp)                                   AS last_seen,
      ARRAY_AGG(DISTINCT attack_type)                  AS attack_types,
      ARRAY_AGG(DISTINCT target_url)                   AS targeted_urls
    FROM waf_alerts WHERE source_ip = $1`, [ip]
  );
  const r = result.rows[0];
  return {
    totalLocalRequests:   parseInt(r.total),
    blockedLocally:       parseInt(r.blocked),
    firstSeenLocally:     r.first_seen,
    lastSeenLocally:      r.last_seen,
    attackTypesLocally:   r.attack_types || [],
    targetedURLs:         r.targeted_urls || [],
  };
}

// ─── Reports ──────────────────────────────────────────────────────────────────
async function getReportData(type, from, to) {
  const fromDate = new Date(from);
  const toDate   = new Date(to);

  const baseFilter = "timestamp BETWEEN $1 AND $2";
  const baseVals   = [fromDate, toDate];

  const [alerts, attackTypes, ipMap, daily] = await Promise.all([
    pool.query(`SELECT * FROM waf_alerts WHERE ${baseFilter} ORDER BY timestamp DESC LIMIT 5000`, baseVals),
    pool.query(`SELECT attack_type AS type, COUNT(*) AS count, COUNT(*) FILTER (WHERE action='blocked') AS blocked FROM waf_alerts WHERE ${baseFilter} GROUP BY attack_type ORDER BY count DESC`, baseVals),
    pool.query(`SELECT source_ip AS ip, country, country_code, COUNT(*) AS total_requests, COUNT(*) FILTER (WHERE action='blocked') AS blocked, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, ARRAY_AGG(DISTINCT attack_type) AS attack_types, ARRAY_AGG(DISTINCT target_url) AS targeted_urls FROM waf_alerts WHERE ${baseFilter} GROUP BY source_ip, country, country_code ORDER BY total_requests DESC LIMIT 50`, baseVals),
    pool.query(`SELECT DATE(timestamp) AS date, COUNT(*) AS total, COUNT(*) FILTER (WHERE action='blocked') AS blocked, COUNT(*) FILTER (WHERE severity='critical') AS critical FROM waf_alerts WHERE ${baseFilter} GROUP BY DATE(timestamp) ORDER BY date`, baseVals),
  ]);

  const totalAlerts  = alerts.rows.map(dbRowToAlert);
  const blockedCount = totalAlerts.filter(a => a.action === "blocked").length;
  const uniqueIPs    = new Set(totalAlerts.map(a => a.sourceIP)).size;
  const criticalCount = totalAlerts.filter(a => a.severity === "critical").length;

  const summary = {
    totalEvents: totalAlerts.length,
    blocked: blockedCount,
    allowed: totalAlerts.length - blockedCount,
    uniqueAttackers: uniqueIPs,
    criticalEvents: criticalCount,
  };

  const base = { generatedAt: new Date(), dateRange: { from: fromDate, to: toDate }, summary, events: totalAlerts };

  if (type === "daily") {
    return { ...base, reportType: "Daily Security Summary", topAttackTypes: attackTypes.rows.map(r => ({ type: r.type, count: parseInt(r.count) })) };
  }
  if (type === "threats") {
    return { ...base, reportType: "Threat Analysis Report", totalThreats: totalAlerts.length, topThreats: ipMap.rows.map(r => ({ ip: r.ip, country: r.country, count: parseInt(r.total_requests), blocked: parseInt(r.blocked), types: r.attack_types })), attackPatterns: attackTypes.rows.map(r => ({ type: r.type, count: parseInt(r.count), blocked: parseInt(r.blocked) })), criticalAlerts: totalAlerts.filter(a => a.severity === "critical") };
  }
  if (type === "ips") {
    return { ...base, reportType: "IP Intelligence Report", profiles: ipMap.rows.map(r => ({ ip: r.ip, country: r.country, countryCode: r.country_code, totalRequests: parseInt(r.total_requests), blocked: parseInt(r.blocked), firstSeen: r.first_seen, lastSeen: r.last_seen, attackTypes: r.attack_types, targetedURLs: r.targeted_urls, riskScore: Math.min(Math.floor((parseInt(r.blocked) / Math.max(parseInt(r.total_requests), 1)) * 100), 99) })), totalUniqueIPs: uniqueIPs, attackPatterns: attackTypes.rows.map(r => ({ type: r.type, count: parseInt(r.count) })) };
  }
  if (type === "trends") {
    return { ...base, reportType: "Security Trends Report", dailyTrend: daily.rows.map(r => ({ date: r.date, total: parseInt(r.total), blocked: parseInt(r.blocked), critical: parseInt(r.critical) })), overallBlockRate: totalAlerts.length > 0 ? ((blockedCount / totalAlerts.length) * 100).toFixed(1) : 0, attackEvolution: attackTypes.rows.map(r => ({ type: r.type, total: parseInt(r.count) })) };
  }

  throw new Error(`Unknown report type: ${type}`);
}

// ─── Row Mappers ──────────────────────────────────────────────────────────────
function dbRowToAlert(r) {
  return {
    id: r.id,
    timestamp: r.timestamp,
    attackType: r.attack_type,
    sourceIP: r.source_ip,
    targetURL: r.target_url,
    severity: r.severity,
    action: r.action,
    country: r.country,
    countryCode: r.country_code,
    requestMethod: r.request_method,
    userAgent: r.user_agent,
    payload: r.payload,
    ruleId: r.rule_id,
    ruleName: r.rule_name,
    matchedSIDs: r.matched_sids,
    snortMsg: r.snort_msg,
    falsePositiveScore: r.false_positive_score,
    cveReference: r.cve_reference,
    device: { os: r.device_os, browser: r.device_browser, deviceType: r.device_type, isMaliciousTool: r.is_malicious_tool, toolName: r.tool_name, fingerprint: r.device_fingerprint },
    network: { forwardedFor: r.forwarded_for, protocol: r.protocol, httpVersion: r.http_version },
    requestSize: r.request_size,
    contentType: r.content_type,
    referer: r.referer,
    acceptLanguage: r.accept_language,
  };
}

function dbRowToIncident(r) {
  return {
    id: r.id, title: r.title, severity: r.severity, status: r.status,
    timeRange: { start: r.start_time, end: r.end_time },
    eventCount: r.event_count,
    affectedEndpoints: r.affected_endpoints || [],
    relatedIPs: r.related_ips || [],
    assignee: r.assignee, notes: r.notes,
    events: [],   // event timeline is not stored per-incident; safe default
    createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

function dbRowToRule(r) {
  return {
    id: r.id, name: r.name, category: r.category, description: r.description,
    enabled: r.enabled, threshold: r.threshold, severity: r.severity, action: r.action,
    createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

async function getThreatMapEvents({ minutes = 60, limit = 200, action = "all" } = {}) {
  const since = new Date(Date.now() - minutes * 60 * 1000);

  const conditions = ["timestamp >= $1", "latitude IS NOT NULL"];
  const values = [since];
  let i = 2;

  if (action && action !== "all") {
    conditions.push(`action = $${i++}`);
    values.push(action);
  }

  values.push(limit);

  const result = await pool.query(
    `SELECT
       id,
       timestamp,
       attack_type   AS "attackType",
       source_ip     AS "sourceIP",
       target_url    AS "targetURL",
       severity,
       action,
       country,
       country_code  AS "countryCode",
       latitude,
       longitude,
       rule_name     AS "ruleName"
     FROM waf_alerts
     WHERE ${conditions.join(" AND ")}
     ORDER BY timestamp DESC
     LIMIT $${i}`,
    values
  );

  return {
    events:  result.rows,
    total:   result.rows.length,
    minutes,
  };
}

// ─── NEW FUNCTION 2 ──────────────────────────────────────────────────────────

async function getThreatMapSummary({ minutes = 60 } = {}) {
  const since = new Date(Date.now() - minutes * 60 * 1000);

  const result = await pool.query(
    `SELECT
       country,
       country_code                                        AS "countryCode",
       AVG(latitude)                                       AS latitude,
       AVG(longitude)                                      AS longitude,
       COUNT(*)                                            AS total,
       COUNT(*) FILTER (WHERE action = 'blocked')          AS blocked,
       COUNT(*) FILTER (WHERE severity = 'critical')       AS critical,
       COUNT(*) FILTER (WHERE severity = 'high')           AS high,
       ARRAY_AGG(DISTINCT attack_type)                     AS "attackTypes"
     FROM waf_alerts
     WHERE timestamp >= $1
       AND latitude IS NOT NULL
     GROUP BY country, country_code
     ORDER BY total DESC
     LIMIT 50`,
    [since]
  );

  return {
    countries: result.rows.map(r => ({
      ...r,
      total:    parseInt(r.total),
      blocked:  parseInt(r.blocked),
      critical: parseInt(r.critical),
      high:     parseInt(r.high),
      latitude:  parseFloat(r.latitude),
      longitude: parseFloat(r.longitude),
    })),
    minutes,
  };
}

module.exports = {
  pool, initDatabase,
  insertAlert, getAlerts, getAlertById, getAlertsByIP, getLiveAlerts,
  getDashboardStats, getAnalytics,
  getIncidents, getIncidentById, upsertIncident, updateIncident,
  getRules, getRuleById, updateRule, createRule, deleteRule,
  blockIP, unblockIP, getBlockedIPs,
  getIPActivity, getReportData, getThreatMapEvents, getThreatMapSummary,
};
