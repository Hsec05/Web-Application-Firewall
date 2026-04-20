/**
 * SOC Dashboard Backend Server — PostgreSQL Edition
 */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const http = require("http");
const db = require("./database");
const store = require("./data/store");
const wafMiddleware = require("./middleware/wafMiddleware");
const { startSimulator, stopSimulator } = require("./simulator/trafficSimulator");
const { startIncidentEngine, seedIncidentsFromAlerts } = require("./incidentEngine");
const { generatePDFReport } = require("./pdfGenerator");
const { writeAuditLog } = require("./routes/auditLogs");
const dashboardRoutes = require("./routes/dashboard");
const alertsRoutes    = require("./routes/alerts");
const ipRoutes        = require("./routes/ipIntelligence");
const incidentsRoutes = require("./routes/incidents");
const rulesRoutes     = require("./routes/rules");
const analyticsRoutes = require("./routes/analytics");
const reportsRoutes   = require("./routes/reports");
const threatMapRoutes = require("./routes/threatMap");
const authRoutes      = require("./routes/auth");
const { router: auditLogsRoutes } = require("./routes/auditLogs");
const settingsRoutes  = require("./routes/settings");
const usersRoutes     = require("./routes/users");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: async (origin, callback) => {
    if (!origin) return callback(null, true);
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return callback(null, true);
    if (/^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01]))/.test(origin)) return callback(null, true);
    if (/\.devtunnels\.ms$/.test(origin)) return callback(null, true);
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) return callback(null, true);

    // ── Log CSRF attempt matching your DB schema ──────────────────
    const logEntry = {
      id:                 require('uuid').v4(),
      timestamp:          new Date(),
      attackType:         'CSRF',
      sourceIP:           'unknown',          // no req object here
      targetURL:          'CORS-preflight',
      severity:           'high',
      action:             'blocked',
      country:            null,
      countryCode:        null,
      latitude:           null,
      longitude:          null,
      requestMethod:      'OPTIONS',          // CORS is always a preflight
      userAgent:          null,
      ruleId:             'WAF-CORS-001',
      ruleName:           'CORS Policy',
      matchedSIDs:        null,
      snortMsg:           null,
      falsePositiveScore: 0,
      cveReference:       null,
      device: {
        os:             'Unknown',
        browser:        'Unknown',
        deviceType:     'Unknown',
        isMaliciousTool: true,
        toolName:       `CSRF from ${origin}`,
        fingerprint:    null,
      },
      network: {
        forwardedFor:   null,
        realIP:         null,
        cfConnectingIP: null,
        protocol:       'https',
        httpVersion:    null,
      },
      requestSize:    0,
      contentType:    null,
      referer:        origin,   // origin IS the referer in CSRF context
      acceptLanguage: null,
    };

    db.insertAlert(logEntry).catch(err => 
      console.error('CORS alert DB write failed:', err.message)
    );
    // ─────────────────────────────────────────────────────────────

    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ["GET","POST","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 60000, max: 300, standardHeaders: true, legacyHeaders: false }));
app.use(wafMiddleware);

app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date(), uptime: process.uptime(), db: "postgresql" }));

app.use("/api/dashboard",  dashboardRoutes);
app.use("/api/alerts",     alertsRoutes);
app.use("/api/ip",         ipRoutes);
app.use("/api/incidents",  incidentsRoutes);
app.use("/api/rules",      rulesRoutes);
app.use("/api/analytics",  analyticsRoutes);
app.use("/api/reports",    reportsRoutes);
app.use("/api/threat-map", threatMapRoutes);
app.use("/api/auth",        authRoutes);
app.use("/api/audit-logs", auditLogsRoutes);
app.use("/api/settings",   settingsRoutes);
app.use("/api/users",      usersRoutes);

app.post("/api/admin/reset", async (req, res) => {
  await db.pool.query("TRUNCATE waf_alerts, waf_incidents, waf_blocked_ips RESTART IDENTITY");
  store.blockedIPs.clear();
  store.alerts.splice(0);
  console.log("🧹  Database reset via API");
  res.json({ success: true, message: "All data cleared from PostgreSQL." });
});

app.post("/api/admin/simulator/start", (req, res) => {
  startSimulator();
  res.json({ success: true, message: "Simulator started" });
});

app.post("/api/admin/simulator/stop", (req, res) => {
  stopSimulator();
  res.json({ success: true, message: "Simulator stopped" });
});

app.get("/api/admin/simulator/status", (req, res) => {
  const { simulatorInterval } = require("./simulator/trafficSimulator");
  res.json({ running: simulatorInterval !== null });
});

// Expose it via an API endpoint
app.get('/api/waf/stats/request-count', (req, res) => {
  try {
    res.json(wafMiddleware.getRequestCount());
  } catch (err) {
    console.error('request-count route error:', err);
    res.status(500).json({ error: err.message });
  }
});

const TARGET_SITE = process.env.TARGET_SITE || "http://localhost:3000";

app.use((req, res) => {
  const targetUrl = new URL(req.originalUrl, TARGET_SITE);

  // express.json() already consumed the body stream — re-serialize it
  // so the target site can read username/password on POST requests
  const bodyData = (req.body && Object.keys(req.body).length > 0)
    ? JSON.stringify(req.body)
    : null;

  const options = {
    hostname: targetUrl.hostname,
    port:     targetUrl.port || 3000,
    path:     targetUrl.pathname + targetUrl.search,
    method:   req.method,
    headers: {
      ...req.headers,
      host:                 targetUrl.host,
      "x-forwarded-for":   req.ip,
      "x-forwarded-proto": req.protocol,
      "x-waf-inspected":   "true",
      // update content-length to match re-serialized body
      ...(bodyData ? {
        "content-type":   "application/json",
        "content-length": Buffer.byteLength(bodyData),
      } : {}),
    },
  };

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxy.on("error", () => {
    res.status(502).send(`
      <html><body style="background:#0a0a0f;color:#e8e8f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
        <div style="text-align:center">
          <div style="font-size:3rem;margin-bottom:1rem">🛑</div>
          <h2>Target Site Unavailable</h2>
          <p style="color:#6b6b80;margin-top:0.5rem">Start NexMart on port 3000 first:</p>
          <code style="background:#13131a;padding:0.5rem 1rem;border-radius:8px;display:inline-block;margin-top:1rem">cd target-site && npm start</code>
        </div>
      </body></html>
    `);
  });

  // write re-serialized body for POST/PUT/PATCH, pipe stream for GET/DELETE
  if (bodyData) {
    proxy.write(bodyData);
    proxy.end();
  } else {
    req.pipe(proxy, { end: true });
  }
});
app.use((err, req, res, next) => {
  if (err.message?.startsWith('CORS:')) {
    return res.status(403).json({ error: err.message });
  }
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});
// ─── Boot ─────────────────────────────────────────────────────────────────────
async function boot() {
  try {
    // Init DB schema, seed rules, load blocked IPs into memory
    const blockedIPs = await db.initDatabase(store.securityRules);
    blockedIPs.forEach(ip => store.blockedIPs.add(ip));

    app.listen(PORT, '0.0.0.0', async () => {
      console.log(`\n🛡️  SOC Dashboard (PostgreSQL) running`);
      console.log(`   ✅ http://localhost:${PORT}`);
      console.log(`   🗄️  Database: ${process.env.DB_NAME || "waf_dashboard"} @ ${process.env.DB_HOST || "localhost"}`);
      console.log(`   💤 Simulator: OFF — start via Postman when needed`);
      console.log(`   ▶  POST http://localhost:${PORT}/api/admin/simulator/start`);
      console.log(`   ⏹  POST http://localhost:${PORT}/api/admin/simulator/stop`);
      console.log(`   ℹ  GET  http://localhost:${PORT}/api/admin/simulator/status\n`);
      await seedIncidentsFromAlerts(); // seed/refresh incidents from existing alerts on boot
      startIncidentEngine();           // then keep running every 60s to pick up new IPs in real-time
      
    });
  } catch (err) {
    console.error("❌  Boot failed:", err.message);
    console.error("   Check your .env DB credentials and that PostgreSQL is running.");
    process.exit(1);
  }
}

// ─── Scheduled Reports Engine ─────────────────────────────────────────────────
// Parses a 5-field cron string and checks if it matches the current minute.
function cronMatches(cronExpr, now) {
  try {
    const [minute, hour, dom, month, dow] = cronExpr.trim().split(/\s+/);
    const match = (field, val) => {
      if (field === "*") return true;
      if (field.includes("/")) {
        const [, step] = field.split("/");
        return val % parseInt(step, 10) === 0;
      }
      if (field.includes(",")) return field.split(",").map(Number).includes(val);
      if (field.includes("-")) {
        const [lo, hi] = field.split("-").map(Number);
        return val >= lo && val <= hi;
      }
      return parseInt(field, 10) === val;
    };
    return (
      match(minute, now.getMinutes()) &&
      match(hour,   now.getHours()) &&
      match(dom,    now.getDate()) &&
      match(month,  now.getMonth() + 1) &&
      match(dow,    now.getDay())
    );
  } catch {
    return false;
  }
}

let _lastScheduledMinute = -1;

async function runScheduledReports() {
  try {
    const { rows } = await db.pool.query(
      `SELECT key, value FROM soc_settings WHERE key LIKE 'reports.%'`
    );
    const cfg = {};
    for (const r of rows) cfg[r.key] = r.value;

    if (!cfg["reports.schedule_enabled"]) return;

    const cron  = cfg["reports.schedule_cron"]  || "0 8 * * 1";
    const type  = cfg["reports.schedule_type"]   || "weekly";
    const email = cfg["reports.schedule_email"]  || "";

    const now = new Date();
    const thisMinute = now.getFullYear() * 525960 + (now.getMonth() * 44640) + (now.getDate() * 1440) + (now.getHours() * 60) + now.getMinutes();

    // Only fire once per matching minute
    if (thisMinute === _lastScheduledMinute) return;
    if (!cronMatches(cron, now)) return;

    _lastScheduledMinute = thisMinute;

    console.log(`📅  Scheduled report firing: type=${type} recipients=${email}`);

    const from  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const to    = new Date();
    const report = await db.getReportData(type, from, to);
    const pdf    = await generatePDFReport(report, type);

    // Log the generation in audit logs
    await writeAuditLog({
      username: "system", role: "system",
      action: "scheduled_report_generated", category: "report",
      target: email, detail: { type, cron, sizeBytes: pdf.length },
      ipAddress: "127.0.0.1", outcome: "success",
    });

    console.log(`📄  Scheduled report generated: ${pdf.length} bytes  →  ${email || "(no recipients)"}`);
    // In production: email the PDF buffer via nodemailer / SendGrid here.
  } catch (err) {
    console.error("Scheduled report error:", err.message);
  }
}

// Check every minute
const _scheduleInterval = setInterval(runScheduledReports, 60_000);
if (_scheduleInterval.unref) _scheduleInterval.unref();

boot();
module.exports = app;
