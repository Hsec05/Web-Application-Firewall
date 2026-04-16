/**
 * Audit Logs Routes — Admin-only SOC compliance trail
 * Every significant action in the dashboard is recorded here.
 * Required for SOC 2 / ISO 27001 compliance.
 */

const express = require("express");
const router  = express.Router();
const db      = require("../database");

// ── Ensure audit log table exists ──────────────────────────────────────────────
async function ensureAuditTable() {
  await db.pool.query(`
    CREATE TABLE IF NOT EXISTS soc_audit_log (
      id          SERIAL PRIMARY KEY,
      timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      user_id     INTEGER,
      username    VARCHAR(80),
      role        VARCHAR(20),
      action      VARCHAR(120) NOT NULL,
      category    VARCHAR(60)  NOT NULL DEFAULT 'general',
      target      TEXT,
      target_id   VARCHAR(120),
      detail      JSONB,
      ip_address  VARCHAR(60),
      user_agent  TEXT,
      outcome     VARCHAR(20) NOT NULL DEFAULT 'success'
    );
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON soc_audit_log(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_username  ON soc_audit_log(username);
    CREATE INDEX IF NOT EXISTS idx_audit_action    ON soc_audit_log(action);
  `);
}

ensureAuditTable().catch(console.error);

// ── Helper exported for use in other routes ────────────────────────────────────
async function writeAuditLog({ userId, username, role, action, category = "general", target, targetId, detail, ipAddress, userAgent, outcome = "success" }) {
  try {
    await db.pool.query(
      `INSERT INTO soc_audit_log
        (user_id, username, role, action, category, target, target_id, detail, ip_address, user_agent, outcome)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [userId, username, role, action, category, target, targetId, detail ? JSON.stringify(detail) : null, ipAddress, userAgent, outcome]
    );
  } catch (err) {
    // Never let audit logging crash the main request
    console.error("Audit log write error:", err.message);
  }
}

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

// ── GET /api/audit-logs ────────────────────────────────────────────────────────
router.get("/", requireAdmin, async (req, res) => {
  try {
    const {
      page     = 1,
      limit    = 50,
      username,
      action,
      category,
      outcome,
      from,
      to,
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const conditions = [];
    const values     = [];
    let   idx        = 1;

    if (username) { conditions.push(`username ILIKE $${idx++}`); values.push(`%${username}%`); }
    if (action)   { conditions.push(`action   ILIKE $${idx++}`); values.push(`%${action}%`);   }
    if (category) { conditions.push(`category = $${idx++}`);     values.push(category);         }
    if (outcome)  { conditions.push(`outcome  = $${idx++}`);     values.push(outcome);           }
    if (from)     { conditions.push(`timestamp >= $${idx++}`);   values.push(from);              }
    if (to)       { conditions.push(`timestamp <= $${idx++}`);   values.push(to);               }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const countRes = await db.pool.query(
      `SELECT COUNT(*) FROM soc_audit_log ${where}`, values
    );
    const total = parseInt(countRes.rows[0].count);

    const dataRes = await db.pool.query(
      `SELECT id, timestamp, username, role, action, category, target, target_id, detail, ip_address, outcome
       FROM soc_audit_log ${where}
       ORDER BY timestamp DESC
       LIMIT $${idx} OFFSET $${idx + 1}`,
      [...values, parseInt(limit), offset]
    );

    // Summary stats
    const statsRes = await db.pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE outcome = 'success') AS success_count,
        COUNT(*) FILTER (WHERE outcome = 'failure') AS failure_count,
        COUNT(DISTINCT username)                     AS unique_users,
        COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS last_24h
      FROM soc_audit_log
    `);

    res.json({
      data:  dataRes.rows,
      total,
      page:  parseInt(page),
      limit: parseInt(limit),
      pages: Math.ceil(total / parseInt(limit)),
      stats: statsRes.rows[0],
    });
  } catch (err) {
    console.error("Audit log fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

// ── GET /api/audit-logs/categories ─────────────────────────────────────────────
router.get("/categories", requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.pool.query(
      `SELECT category, COUNT(*) as count FROM soc_audit_log GROUP BY category ORDER BY count DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch categories" });
  }
});

module.exports = { router, writeAuditLog };
