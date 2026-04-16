/**
 * Auth Routes — JWT-based authentication with forgot-password via token
 * Dependencies: npm install jsonwebtoken bcryptjs
 */

const express  = require("express");
const router   = express.Router();
const crypto   = require("crypto");
const { Pool } = require("pg");

// Lazy-load optional deps so the server still boots if not installed yet
let jwt, bcrypt;
try { jwt    = require("jsonwebtoken"); } catch { jwt    = null; }
try { bcrypt = require("bcryptjs");     } catch { bcrypt = null; }

const JWT_SECRET  = process.env.JWT_SECRET  || "soc-dashboard-super-secret-key-change-in-prod";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "24h";

// Reuse the shared PG pool from database.js
const db = require("../database");
const { writeAuditLog } = require("./auditLogs");

// ── Ensure users & reset_tokens tables exist ──────────────────────────────────
async function ensureAuthTables() {
  await db.pool.query(`
    CREATE TABLE IF NOT EXISTS soc_users (
      id           SERIAL PRIMARY KEY,
      username     VARCHAR(80)  UNIQUE NOT NULL,
      email        VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role         VARCHAR(20)  NOT NULL DEFAULT 'analyst',
      created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS soc_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES soc_users(id) ON DELETE CASCADE,
      token      VARCHAR(128) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used       BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Seed a default admin account if no users exist
  if (bcrypt) {
    const { rows } = await db.pool.query("SELECT COUNT(*) FROM soc_users");
    if (parseInt(rows[0].count) === 0) {
      const hash = await bcrypt.hash("admin123", 10);
      await db.pool.query(
        `INSERT INTO soc_users (username, email, password_hash, role)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        ["admin", "admin@secdashboard.local", hash, "admin"]
      );
      console.log("🔐  Default admin created  →  admin / admin123");
    }
  }
}

ensureAuthTables().catch(console.error);

// ── Helpers ───────────────────────────────────────────────────────────────────
function missingDeps(res) {
  return res.status(503).json({
    error: "Auth dependencies not installed. Run: npm install jsonwebtoken bcryptjs",
  });
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

// ── POST /api/auth/register ────────────────────────────────────────────────────
router.post("/register", async (req, res) => {
  if (!jwt || !bcrypt) return missingDeps(res);

  const { username, email, password, role } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "username, email and password are required" });

  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });

  // Validate role — only accept known roles, default to analyst
  const VALID_ROLES = ["admin", "analyst", "viewer"];
  const assignedRole = VALID_ROLES.includes(role) ? role : "analyst";

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.pool.query(
      `INSERT INTO soc_users (username, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, role, created_at`,
      [username.trim(), email.trim().toLowerCase(), hash, assignedRole]
    );
    const user  = rows[0];
    const token = makeToken(user);
    await writeAuditLog({ userId: user.id, username: user.username, role: user.role, action: "user_created", category: "user", target: user.username, targetId: String(user.id), ipAddress: req.ip, outcome: "success" });
    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === "23505")
      return res.status(409).json({ error: "Username or email already exists" });
    console.error("Register error:", err.message);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ── POST /api/auth/login ───────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
  if (!jwt || !bcrypt) return missingDeps(res);

  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "username and password are required" });

  try {
    const { rows } = await db.pool.query(
      "SELECT * FROM soc_users WHERE username = $1 OR email = $1",
      [username.trim()]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await writeAuditLog({ username: username.trim(), action: "login_failed", category: "auth", target: "dashboard", ipAddress: req.ip, outcome: "failure" });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Block deactivated accounts after password check (to avoid user enumeration)
    if (user.is_active === false) {
      await writeAuditLog({ userId: user.id, username: user.username, role: user.role, action: "login_blocked_inactive", category: "auth", target: "dashboard", ipAddress: req.ip, outcome: "failure" });
      return res.status(403).json({ error: "Your account has been deactivated. Please contact your administrator." });
    }

    const token = makeToken(user);

    // Update last_login timestamp
    await db.pool.query("UPDATE soc_users SET last_login = NOW() WHERE id = $1", [user.id]).catch(() => {});

    await writeAuditLog({ userId: user.id, username: user.username, role: user.role, action: "login", category: "auth", target: "dashboard", ipAddress: req.ip, outcome: "success" });

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ── POST /api/auth/forgot-password ────────────────────────────────────────────
// Accepts: { email }
// In prod this would send an email — here we return the link so devs can test it.
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "email is required" });

  try {
    const { rows } = await db.pool.query(
      "SELECT id, email FROM soc_users WHERE email = $1",
      [email.trim().toLowerCase()]
    );

    // Always return 200 to prevent email enumeration
    if (!rows[0]) {
      return res.json({ message: "If that email exists, a reset link has been sent." });
    }

    const user      = rows[0];
    const rawToken  = crypto.randomBytes(48).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Invalidate old tokens for this user
    await db.pool.query(
      "UPDATE soc_reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE",
      [user.id]
    );

    await db.pool.query(
      "INSERT INTO soc_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, rawToken, expiresAt]
    );

    const frontendUrl  = process.env.FRONTEND_URL || "http://localhost:8080";
    const resetLink    = `${frontendUrl}/reset-password?token=${rawToken}`;

    // In production: send email here via nodemailer / SendGrid / etc.
    console.log(`\n📧  Password reset link for ${email}:\n   ${resetLink}\n`);

    res.json({
      message: "If that email exists, a reset link has been sent.",
      // DEV ONLY — remove this field in production:
      _devResetLink: resetLink,
    });
  } catch (err) {
    console.error("Forgot-password error:", err.message);
    res.status(500).json({ error: "Request failed" });
  }
});

// ── POST /api/auth/reset-password ─────────────────────────────────────────────
// Accepts: { token, newPassword }
router.post("/reset-password", async (req, res) => {
  if (!bcrypt) return missingDeps(res);

  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "token and newPassword are required" });

  if (newPassword.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });

  try {
    const { rows } = await db.pool.query(
      `SELECT rt.id, rt.user_id, rt.expires_at, rt.used
       FROM soc_reset_tokens rt
       WHERE rt.token = $1`,
      [token]
    );

    const record = rows[0];
    if (!record)     return res.status(400).json({ error: "Invalid or expired reset link" });
    if (record.used) return res.status(400).json({ error: "This reset link has already been used" });
    if (new Date(record.expires_at) < new Date())
      return res.status(400).json({ error: "Reset link has expired — please request a new one" });

    const hash = await bcrypt.hash(newPassword, 10);

    await db.pool.query(
      "UPDATE soc_users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
      [hash, record.user_id]
    );

    await db.pool.query(
      "UPDATE soc_reset_tokens SET used = TRUE WHERE id = $1",
      [record.id]
    );

    res.json({ message: "Password updated successfully. You can now log in." });
  } catch (err) {
    console.error("Reset-password error:", err.message);
    res.status(500).json({ error: "Reset failed" });
  }
});

// ── GET /api/auth/verify-token ─────────────────────────────────────────────────
// Accepts: { token } as query param — checks if a reset token is still valid
router.get("/verify-token", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ valid: false });

  try {
    const { rows } = await db.pool.query(
      `SELECT expires_at, used FROM soc_reset_tokens WHERE token = $1`,
      [token]
    );
    const record = rows[0];
    if (!record || record.used || new Date(record.expires_at) < new Date())
      return res.json({ valid: false });

    res.json({ valid: true });
  } catch {
    res.json({ valid: false });
  }
});

// ── POST /api/auth/me ──────────────────────────────────────────────────────────
// Validates a JWT and returns the user payload
router.get("/me", (req, res) => {
  if (!jwt) return missingDeps(res);
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).json({ error: "No token provided" });

  try {
    const payload = jwt.verify(authHeader.slice(7), JWT_SECRET);
    res.json({ user: payload });
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

module.exports = router;
