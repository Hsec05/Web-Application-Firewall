/**
 * In-memory data store for WAF security data.
 * In production, replace with a real database (PostgreSQL, MongoDB, etc.)
 */

const { v4: uuidv4 } = require("uuid");

// ─── Attack Patterns for WAF Detection ───────────────────────────────────────

const ATTACK_PATTERNS = {
  SQLi: [
    /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bUNION\b|\bEXEC\b)/i,
    /('|--|;|\/\*|\*\/|xp_)/i,
    /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i,
    /'\s*(OR|AND)\s*'[^']*'\s*=\s*'[^']*'/i,
  ],
  XSS: [
    /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
    /javascript\s*:/i,
    /on\w+\s*=\s*["']?[^"'>]*/i,
    /<img[^>]+onerror\s*=/i,
    /eval\s*\(/i,
  ],
  "Path Traversal": [
    /\.\.\//g,
    /\.\.%2F/i,
    /%2e%2e%2f/i,
    /\/etc\/passwd/i,
    /\/proc\/self/i,
  ],
  RCE: [
    /\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i,
    /\$\([^)]+\)/,
    /`[^`]{3,}`/,
    /\b(wget|curl|bash|sh|python|perl|ruby)\b/i,
  ],
  CSRF: [
    /x-forwarded-for.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
  ],
};

const SEVERITY_MAP = {
  SQLi:                  "critical",
  XSS:                   "high",
  "Brute Force":         "medium",
  DDoS:                  "high",
  "Path Traversal":      "high",
  RCE:                   "critical",
  CSRF:                  "medium",
  XXE:                   "critical",
  SSRF:                  "critical",
  "Open Redirect":       "medium",
  NoSQLi:                "high",
  "Prototype Pollution": "high",
  "HTTP Smuggling":      "critical",
  Auth:                  "critical",
  Recon:                 "medium",
  Other:                 "low",
};

// ─── Seed Data ────────────────────────────────────────────────────────────────

const COUNTRIES = [
  { country: "China", countryCode: "CN", city: "Beijing" },
  { country: "Russia", countryCode: "RU", city: "Moscow" },
  { country: "United States", countryCode: "US", city: "New York" },
  { country: "Brazil", countryCode: "BR", city: "São Paulo" },
  { country: "India", countryCode: "IN", city: "Mumbai" },
  { country: "Germany", countryCode: "DE", city: "Berlin" },
  { country: "North Korea", countryCode: "KP", city: "Pyongyang" },
  { country: "Iran", countryCode: "IR", city: "Tehran" },
  { country: "Vietnam", countryCode: "VN", city: "Hanoi" },
  { country: "Ukraine", countryCode: "UA", city: "Kyiv" },
  { country: "Romania", countryCode: "RO", city: "Bucharest" },
  { country: "Netherlands", countryCode: "NL", city: "Amsterdam" },
];

const TARGET_URLS = [
  "/api/login",
  "/api/users",
  "/admin/dashboard",
  "/api/payments",
  "/wp-admin",
  "/phpmyadmin",
  "/api/data/export",
  "/.env",
  "/api/v1/auth",
  "/graphql",
  "/api/v2/users",
  "/.git/config",
  "/api/admin",
  "/backup.sql",
];

const PAYLOADS = {
  SQLi:                  ["'; DROP TABLE users; --", "' OR '1'='1", "1 UNION SELECT * FROM users--", "admin'--"],
  XSS:                   ["<script>alert(1)</script>", "<img onerror=alert(1) src=x>", "javascript:void(0)"],
  "Path Traversal":      ["../../etc/passwd", "../../../etc/shadow", "..%2F..%2Fetc%2Fpasswd"],
  RCE:                   ["`whoami`", "$(cat /etc/passwd)", "system('ls -la')"],
  XXE:                   ["<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"],
  SSRF:                  ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin", "file:///etc/passwd"],
  "Open Redirect":       ["https://evil.com", "//evil.com/phishing", "javascript:alert(document.cookie)"],
  NoSQLi:                ["{\"$where\": \"this.password == 'x'\"}", "{\"$gt\": \"\"}", "{\"username\": {\"$ne\": null}}"],
  "Prototype Pollution": ["__proto__[admin]=true", "constructor.prototype.isAdmin=true"],
  "HTTP Smuggling":      ["Transfer-Encoding: chunked\r\nContent-Length: 4"],
  Auth:                  ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."],
  Recon:                 ["/.env", "/.git/config", "/backup.sql", "/wp-config.php"],
};

const ISPS = ["CloudFlare", "Amazon AWS", "Google Cloud", "DigitalOcean", "Linode", "Vultr", "OVH", "Hetzner", "Unknown ISP"];

const ATTACK_TYPES = [
  "SQLi", "XSS", "Brute Force", "DDoS", "Path Traversal", "RCE", "CSRF",
  "XXE", "SSRF", "Open Redirect", "NoSQLi", "Prototype Pollution",
  "HTTP Smuggling", "Auth", "Recon", "Other",
];

const USER_AGENTS = [
  "Mozilla/5.0 (compatible; Malicious/1.0)",
  "sqlmap/1.7.8#stable",
  "Nikto/2.1.6",
  "python-requests/2.28.2",
  "curl/7.88.1",
  "masscan/1.3",
  "Go-http-client/1.1",
  "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP() {
  return `${randomInt(1, 254)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;
}

function randomDate(start, end) {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}

function generateRuleId(attackType) {
  const prefixes = {
    SQLi: "SQLi", XSS: "XSS", "Brute Force": "BF", DDoS: "DDOS",
    "Path Traversal": "PT", RCE: "RCE", CSRF: "CSRF",
    XXE: "XXE", SSRF: "SSRF", "Open Redirect": "OR", NoSQLi: "NOSQL",
    "Prototype Pollution": "PP", "HTTP Smuggling": "SMUG",
    Auth: "AUTH", Recon: "RECON", Other: "GEN",
  };
  return `WAF-${prefixes[attackType] || "GEN"}-${randomInt(1000, 9999)}`;
}

// ─── Security Rules (persistent in memory) ───────────────────────────────────

const securityRules = [
  {
    id: "rule-sqli-001",
    name: "SQL Injection Protection",
    category: "SQLi",
    description: "Detects and blocks SQL injection attempts in query parameters and request body",
    enabled: true,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-01-01"),
    updatedAt: new Date("2024-06-15"),
  },
  {
    id: "rule-xss-001",
    name: "XSS Attack Prevention",
    category: "XSS",
    description: "Filters cross-site scripting payloads from user input",
    enabled: true,
    threshold: 1,
    severity: "high",
    action: "blocked",
    createdAt: new Date("2024-01-01"),
    updatedAt: new Date("2024-05-20"),
  },
  {
    id: "rule-bf-001",
    name: "Brute Force Protection",
    category: "Brute Force",
    description: "Limits login attempts to prevent credential stuffing",
    enabled: true,
    threshold: 5,
    severity: "medium",
    action: "blocked",
    createdAt: new Date("2024-01-01"),
    updatedAt: new Date("2024-04-10"),
  },
  {
    id: "rule-ddos-001",
    name: "DDoS Mitigation",
    category: "DDoS",
    description: "Rate limiting and traffic analysis for DDoS protection",
    enabled: true,
    threshold: 1000,
    severity: "high",
    action: "blocked",
    createdAt: new Date("2024-01-01"),
    updatedAt: new Date("2024-07-01"),
  },
  {
    id: "rule-pt-001",
    name: "Path Traversal Prevention",
    category: "Path Traversal",
    description: "Blocks directory traversal attempts",
    enabled: true,
    threshold: 1,
    severity: "high",
    action: "blocked",
    createdAt: new Date("2024-02-15"),
    updatedAt: new Date("2024-06-01"),
  },
  {
    id: "rule-rce-001",
    name: "Remote Code Execution Guard",
    category: "RCE",
    description: "Prevents remote code execution attacks",
    enabled: false,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-03-01"),
    updatedAt: new Date("2024-03-01"),
  },
  {
    id: "rule-csrf-001",
    name: "CSRF Protection",
    category: "CSRF",
    description: "Validates origin and referer headers to prevent cross-site request forgery",
    enabled: true,
    threshold: 1,
    severity: "medium",
    action: "blocked",
    createdAt: new Date("2024-03-15"),
    updatedAt: new Date("2024-06-20"),
  },
  {
    id: "rule-xxe-001",
    name: "XXE Injection Blocker",
    category: "XXE",
    description: "Detects XML External Entity attacks that attempt to read local files or trigger SSRF via XML parsers",
    enabled: true,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-ssrf-001",
    name: "SSRF Detection",
    category: "SSRF",
    description: "Blocks Server-Side Request Forgery attempts targeting internal IPs, metadata services, and non-HTTP schemes",
    enabled: true,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-or-001",
    name: "Open Redirect Prevention",
    category: "Open Redirect",
    description: "Prevents attackers from using your site as a redirect relay to phishing or malware pages",
    enabled: true,
    threshold: 3,
    severity: "medium",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-nosql-001",
    name: "NoSQL Injection Guard",
    category: "NoSQLi",
    description: "Detects MongoDB operator injection attacks using $where, $regex, $gt, $ne and JavaScript execution",
    enabled: true,
    threshold: 1,
    severity: "high",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-pp-001",
    name: "Prototype Pollution Blocker",
    category: "Prototype Pollution",
    description: "Blocks __proto__ and constructor.prototype manipulation attempts in query parameters and request bodies",
    enabled: true,
    threshold: 1,
    severity: "high",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-smug-001",
    name: "HTTP Request Smuggling Detection",
    category: "HTTP Smuggling",
    description: "Detects conflicting Transfer-Encoding and Content-Length headers used in HTTP desync attacks",
    enabled: true,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-auth-001",
    name: "JWT Tampering Detection",
    category: "Auth",
    description: "Detects JWT tokens with alg:none, weak signatures, or malformed claims used to bypass authentication",
    enabled: true,
    threshold: 1,
    severity: "critical",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
  {
    id: "rule-recon-001",
    name: "Recon & Scanner Detection",
    category: "Recon",
    description: "Identifies automated scanners (Nikto, Burp, masscan, gobuster) and sensitive file enumeration attempts",
    enabled: true,
    threshold: 3,
    severity: "medium",
    action: "blocked",
    createdAt: new Date("2024-04-01"),
    updatedAt: new Date("2024-04-01"),
  },
];

// ─── Seed Alert Generator ─────────────────────────────────────────────────────

function generateSeedAlerts(count = 200) {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const alerts = [];

  for (let i = 0; i < count; i++) {
    const attackType = randomItem(ATTACK_TYPES);
    const severity = SEVERITY_MAP[attackType] || randomItem(["critical", "high", "medium", "low", "info"]);
    const action = severity === "critical" || severity === "high" ? "blocked" : Math.random() > 0.3 ? "blocked" : "allowed";
    const countryData = randomItem(COUNTRIES);
    const payloads = PAYLOADS[attackType];

    alerts.push({
      id: `alert-seed-${i + 1}-${uuidv4().slice(0, 8)}`,
      timestamp: randomDate(weekAgo, now),
      attackType,
      sourceIP: randomIP(),
      targetURL: randomItem(TARGET_URLS),
      severity,
      action,
      country: countryData.country,
      countryCode: countryData.countryCode,
      requestMethod: randomItem(["GET", "POST", "PUT", "DELETE", "PATCH"]),
      userAgent: randomItem(USER_AGENTS),
      payload: payloads ? randomItem(payloads) : undefined,
      ruleId: generateRuleId(attackType),
      ruleName: `${attackType} Detection Rule`,
    });
  }

  return alerts.sort((a, b) => b.timestamp - a.timestamp);
}

function generateSeedIncidents(alerts) {
  const now = new Date();
  const incidents = [];

  const criticals = alerts.filter(a => a.severity === "critical" || a.severity === "high");
  const sqliAlerts = alerts.filter(a => a.attackType === "SQLi");
  const bruteAlerts = alerts.filter(a => a.attackType === "Brute Force");
  const xssAlerts = alerts.filter(a => a.attackType === "XSS");
  const ddosAlerts = alerts.filter(a => a.attackType === "DDoS");

  if (sqliAlerts.length >= 3) {
    incidents.push({
      id: "INC-001",
      title: "Coordinated SQL Injection Campaign",
      timeRange: {
        start: new Date(now.getTime() - 2 * 60 * 60 * 1000),
        end: now,
      },
      severity: "critical",
      status: "investigating",
      eventCount: Math.min(sqliAlerts.length, 45),
      affectedEndpoints: ["/api/login", "/api/users", "/api/data/export"],
      relatedIPs: [...new Set(sqliAlerts.slice(0, 6).map(a => a.sourceIP))],
      events: sqliAlerts.slice(0, 15),
      assignee: "Security Team",
      notes: "Multiple SQLi attempts from distributed IPs targeting authentication and data endpoints. Patterns suggest automated tooling (sqlmap signature detected).",
    });
  }

  if (bruteAlerts.length >= 2) {
    incidents.push({
      id: "INC-002",
      title: "Brute Force Attack on Admin Portal",
      timeRange: {
        start: new Date(now.getTime() - 6 * 60 * 60 * 1000),
        end: new Date(now.getTime() - 4 * 60 * 60 * 1000),
      },
      severity: "high",
      status: "resolved",
      eventCount: 342,
      affectedEndpoints: ["/admin/dashboard", "/wp-admin"],
      relatedIPs: [...new Set(bruteAlerts.slice(0, 4).map(a => a.sourceIP))],
      events: bruteAlerts.slice(0, 10),
      assignee: "John Doe",
      notes: "Automated brute force blocked after 342 failed attempts. Source IPs added to blocklist.",
    });
  }

  if (xssAlerts.length >= 1) {
    incidents.push({
      id: "INC-003",
      title: "XSS Injection Attempts on User Profile",
      timeRange: {
        start: new Date(now.getTime() - 12 * 60 * 60 * 1000),
        end: new Date(now.getTime() - 11 * 60 * 60 * 1000),
      },
      severity: "medium",
      status: "closed",
      eventCount: xssAlerts.length,
      affectedEndpoints: ["/api/users"],
      relatedIPs: [...new Set(xssAlerts.slice(0, 2).map(a => a.sourceIP))],
      events: xssAlerts.slice(0, 5),
      notes: "Single attacker XSS attempt, successfully blocked. No data exfiltration detected.",
    });
  }

  if (ddosAlerts.length >= 1) {
    incidents.push({
      id: "INC-004",
      title: "DDoS Traffic Spike Detected",
      timeRange: {
        start: new Date(now.getTime() - 3 * 60 * 60 * 1000),
        end: new Date(now.getTime() - 2.5 * 60 * 60 * 1000),
      },
      severity: "high",
      status: "open",
      eventCount: ddosAlerts.length * 100,
      affectedEndpoints: ["/api/v1/auth", "/graphql"],
      relatedIPs: [...new Set(ddosAlerts.slice(0, 8).map(a => a.sourceIP))],
      events: ddosAlerts.slice(0, 20),
      assignee: "NOC Team",
      notes: "High volume traffic from multiple botnets. Rate limiting engaged. Monitoring for escalation.",
    });
  }

  return incidents;
}

// ─── Store Initialization ─────────────────────────────────────────────────────
// Pass --fresh flag to start with zero data: node server.js --fresh

const FRESH_START = process.argv.includes("--fresh");

const alerts = FRESH_START ? [] : generateSeedAlerts(200);
const incidents = FRESH_START ? [] : generateSeedIncidents(generateSeedAlerts(200));

if (FRESH_START) {
  console.log("🧹  Fresh start — seed data cleared. Only live simulator traffic will appear.");
}

// Brute force tracker: ip -> { count, firstAttempt }
const bruteForceTracker = new Map();

// Blocked IPs set
const blockedIPs = new Set();

// Rate limit tracker: ip -> [timestamps]
const rateLimitTracker = new Map();

// Attack threshold tracker: ip -> { attackType -> { count, firstAttempt } }
// Tracks all attack types for threshold-based blocking
const attackThresholdTracker = new Map();

module.exports = {
  alerts,
  incidents,
  securityRules,
  blockedIPs,
  bruteForceTracker,
  rateLimitTracker,
  attackThresholdTracker,
  ATTACK_PATTERNS,
  SEVERITY_MAP,
  COUNTRIES,
  TARGET_URLS,
  PAYLOADS,
  ISPS,
  ATTACK_TYPES,
  USER_AGENTS,
  // helpers
  randomItem,
  randomInt,
  randomIP,
  generateRuleId,
  generateSeedAlerts,
};