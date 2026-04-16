/**
 * User Management Routes — Admin-only
 * List users, update roles, deactivate / reactivate accounts.
 */

const express = require("express");
const router  = express.Router();
const db      = require("../database");
const { writeAuditLog } = require("./auditLogs");

// ── Ensure is_active column exists ─────────────────────────────────────────────
async function ensureUserColumns() {
  await db.pool.query(`
    ALTER TABLE soc_users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE soc_users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
  `);
}
ensureUserColumns().catch(console.error);

// ── Auth middleware ─────────────────────────────────────────────────────────────
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

// ── GET /api/users ─────────────────────────────────────────────────────────────
router.get("/", requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.pool.query(
      `SELECT id, username, email, role, is_active, last_login, created_at, updated_at
       FROM soc_users ORDER BY created_at DESC`
    );
    res.json({ data: rows, total: rows.length });
  } catch (err) {
    console.error("Users fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// ── PATCH /api/users/:id ───────────────────────────────────────────────────────
// Allows updating role and/or is_active
router.patch("/:id", requireAdmin, async (req, res) => {
  const { role, is_active } = req.body;
  const userId = parseInt(req.params.id);

  // Prevent admin from deactivating themselves
  if (req.authUser.id === userId && is_active === false) {
    return res.status(400).json({ error: "You cannot deactivate your own account" });
  }

  const VALID_ROLES = ["admin", "analyst", "viewer"];
  if (role && !VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}` });
  }

  try {
    const setClauses = [];
    const values     = [];
    let   idx        = 1;

    if (role      !== undefined) { setClauses.push(`role = $${idx++}`);      values.push(role); }
    if (is_active !== undefined) { setClauses.push(`is_active = $${idx++}`); values.push(is_active); }

    if (setClauses.length === 0) return res.status(400).json({ error: "Nothing to update" });

    setClauses.push(`updated_at = NOW()`);
    values.push(userId);

    const { rows } = await db.pool.query(
      `UPDATE soc_users SET ${setClauses.join(", ")} WHERE id = $${idx}
       RETURNING id, username, email, role, is_active, last_login, created_at, updated_at`,
      values
    );

    if (!rows[0]) return res.status(404).json({ error: "User not found" });
    await writeAuditLog({
      userId: req.authUser.id, username: req.authUser.username, role: req.authUser.role,
      action: is_active === false ? "user_deactivated" : is_active === true ? "user_reactivated" : "user_role_changed",
      category: "user", target: rows[0].username, targetId: String(userId),
      detail: { role, is_active }, ipAddress: req.ip, outcome: "success",
    });
    res.json(rows[0]);
  } catch (err) {
    console.error("User update error:", err.message);
    res.status(500).json({ error: "Failed to update user" });
  }
});

// ── DELETE /api/users/:id ──────────────────────────────────────────────────────
// Hard delete — use with caution. Prefer deactivation (PATCH is_active: false)
router.delete("/:id", requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  if (req.authUser.id === userId) {
    return res.status(400).json({ error: "You cannot delete your own account" });
  }

  try {
    const { rowCount } = await db.pool.query("DELETE FROM soc_users WHERE id = $1", [userId]);
    if (rowCount === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true });
  } catch (err) {
    console.error("User delete error:", err.message);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

module.exports = router;
