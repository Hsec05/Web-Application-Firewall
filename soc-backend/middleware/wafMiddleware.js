const db = require("../database");
const { v4: uuidv4 } = require("uuid");
const store = require("../data/store");
const { matchSnortRules, getMatchedSIDs, isWhitelisted } = require("./snortRules");
const geoip = require("../geoip");
const wafConfig = require("../wafConfig");

// At the top of your WAF middleware file
let totalRequestCount = 0;
let falsePositiveCount = 0;  
let countResetTime = Date.now();

// ─── Rules Cache (prevents a DB round-trip on every single request) ───────────
// Rules change rarely (only when admin edits them). Cache for 10 seconds so
// the WAF always uses near-live rules without hammering the DB pool.
let _rulesCache     = null;
let _rulesCacheTime = 0;
const RULES_CACHE_TTL_MS = 10_000; // 10 seconds

async function getCachedRules() {
  const now = Date.now();
  if (_rulesCache && (now - _rulesCacheTime) < RULES_CACHE_TTL_MS) {
    return _rulesCache;
  }
  try {
    _rulesCache     = await db.getRules();
    _rulesCacheTime = now;
    return _rulesCache;
  } catch (e) {
    // If DB is under pressure and getRules fails, return stale cache or fallback
    return _rulesCache || store.securityRules;
  }
}

// Call this from the Rules route after any rule is saved/updated/deleted
// so the cache is immediately invalidated and the WAF picks up changes.
function invalidateRulesCache() {
  _rulesCache     = null;
  _rulesCacheTime = 0;
}

// ─── Device & Browser Fingerprinting ─────────────────────────────────────────

function parseDeviceInfo(userAgent = "") {
  let os = "Unknown OS";
  let browser = "Unknown Browser";
  let deviceType = "Desktop";
  let isMaliciousTool = false;
  let toolName = null;

  if (/windows nt 10/i.test(userAgent)) os = "Windows 10/11";
  else if (/windows nt 6\.3/i.test(userAgent)) os = "Windows 8.1";
  else if (/windows nt 6\.1/i.test(userAgent)) os = "Windows 7";
  else if (/macintosh|mac os x/i.test(userAgent)) os = "macOS";
  else if (/linux/i.test(userAgent) && !/android/i.test(userAgent)) os = "Linux";
  else if (/android/i.test(userAgent)) os = "Android";
  else if (/iphone|ipad/i.test(userAgent)) os = "iOS";
  else if (/ubuntu/i.test(userAgent)) os = "Ubuntu";
  else if (/kali/i.test(userAgent)) os = "Kali Linux";

  if (/mobile|android|iphone/i.test(userAgent)) deviceType = "Mobile";
  else if (/ipad|tablet/i.test(userAgent)) deviceType = "Tablet";
  else if (/bot|crawler|spider/i.test(userAgent)) deviceType = "Bot";

  const toolPatterns = [
    { pattern: /sqlmap/i, name: "sqlmap (SQL injection tool)" },
    { pattern: /nikto/i, name: "Nikto (web scanner)" },
    { pattern: /masscan/i, name: "masscan (port scanner)" },
    { pattern: /nmap/i, name: "nmap (network scanner)" },
    { pattern: /dirbuster/i, name: "DirBuster (dir enumeration)" },
    { pattern: /gobuster/i, name: "Gobuster (dir enumeration)" },
    { pattern: /hydra/i, name: "Hydra (brute force tool)" },
    { pattern: /metasploit/i, name: "Metasploit Framework" },
    { pattern: /acunetix/i, name: "Acunetix (web scanner)" },
    { pattern: /burpsuite|burp suite/i, name: "Burp Suite (web proxy)" },
    { pattern: /zgrab/i, name: "zgrab (banner grabber)" },
    { pattern: /python-requests/i, name: "Python Requests (scripted)" },
    { pattern: /go-http-client/i, name: "Go HTTP Client (scripted)" },
    { pattern: /curl\//i, name: "cURL (command-line tool)" },
    { pattern: /wget\//i, name: "wget (file downloader)" },
  ];

  for (const { pattern, name } of toolPatterns) {
    if (pattern.test(userAgent)) {
      isMaliciousTool = true;
      toolName = name;
      break;
    }
  }

  if (!isMaliciousTool) {
    if (/edg\//i.test(userAgent)) browser = "Microsoft Edge";
    else if (/opr\//i.test(userAgent)) browser = "Opera";
    else if (/chrome\//i.test(userAgent)) browser = "Chrome";
    else if (/firefox\//i.test(userAgent)) browser = "Firefox";
    else if (/safari\//i.test(userAgent) && !/chrome/i.test(userAgent)) browser = "Safari";
    else if (/msie|trident/i.test(userAgent)) browser = "Internet Explorer";
  }

  return { os, browser: isMaliciousTool ? toolName : browser, deviceType: isMaliciousTool ? "Attack Tool" : deviceType, isMaliciousTool, toolName, rawUserAgent: userAgent };
}

function buildDeviceFingerprint(req) {
  const components = [req.headers["user-agent"]||"", req.headers["accept-language"]||"", req.headers["accept-encoding"]||"", req.headers["accept"]||"", req.headers["connection"]||""].join("|");
  let hash = 0;
  for (let i = 0; i < components.length; i++) { hash = (hash << 5) - hash + components.charCodeAt(i); hash |= 0; }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

function getRealIP(req) {
  const forwarded = req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.headers["cf-connecting-ip"] || req.headers["x-client-ip"];
  if (forwarded) return forwarded.split(",")[0].trim().replace("::ffff:", "");
  const raw = req.ip || req.socket?.remoteAddress || "0.0.0.0";
  return raw.replace("::ffff:", "").replace("::1", "127.0.0.1");
}

function checkBruteForce(ip, threshold = 5) {
  const now = Date.now();
  const window = 5 * 60 * 1000;
  const entry = store.bruteForceTracker.get(ip) || { count: 0, firstAttempt: now };
  if (now - entry.firstAttempt > window) { store.bruteForceTracker.set(ip, { count: 1, firstAttempt: now }); return false; }
  entry.count++;
  store.bruteForceTracker.set(ip, entry);
  return entry.count >= threshold;
}

function checkRateLimit(ip, threshold) {
  // Use live config value if no explicit threshold passed
  const effectiveThreshold = threshold ?? wafConfig.getRateLimitRpm();
  const now = Date.now();
  const window = 60 * 1000;
  const timestamps = store.rateLimitTracker.get(ip) || [];
  const recent = timestamps.filter((t) => now - t < window);
  recent.push(now);
  store.rateLimitTracker.set(ip, recent);
  return recent.length > effectiveThreshold;
}

function checkAttackThreshold(ip, attackType, threshold = 1, windowMinutes = 5) {
  const now = Date.now();
  const window = windowMinutes * 60 * 1000;
  
  // Get or create IP tracker
  if (!store.attackThresholdTracker.has(ip)) {
    store.attackThresholdTracker.set(ip, new Map());
  }
  
  const ipTracker = store.attackThresholdTracker.get(ip);
  const entry = ipTracker.get(attackType) || { count: 0, firstAttempt: now, attacks: [] };
  
  // Reset if window expired
  if (now - entry.firstAttempt > window) {
    ipTracker.set(attackType, { count: 1, firstAttempt: now, attacks: [now] });
    return 1 >= threshold; // Return true if threshold is 1
  }
  
  // Increment count
  entry.count++;
  entry.attacks.push(now);
  ipTracker.set(attackType, entry);
  
  return entry.count >= threshold;
}

/**
 * Cleanup old attack tracker entries to prevent memory leaks
 * Called periodically to remove expired entries
 */
function cleanupAttackTracker() {
  const now = Date.now();
  const window = 10 * 60 * 1000; // 10 minutes
  
  for (const [ip, ipTracker] of store.attackThresholdTracker.entries()) {
    // Guard: skip if inner value is not a Map (defensive against corruption)
    if (!(ipTracker instanceof Map)) {
      store.attackThresholdTracker.delete(ip);
      continue;
    }
    for (const [attackType, entry] of ipTracker.entries()) {
      if (now - entry.firstAttempt > window) {
        ipTracker.delete(attackType);
      }
    }
    // Remove IP entry if no attack types remain
    if (ipTracker.size === 0) {
      store.attackThresholdTracker.delete(ip);
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupAttackTracker, 5 * 60 * 1000);

// ─── Blocked-IP log throttle ──────────────────────────────────────────────────
// Prevents a single blocked IP flooding the attack log with thousands of
// identical "IP Blocklist" entries. Strategy:
//   First request after a block (or after the window expires): log immediately.
//   Subsequent requests within BLOCKED_LOG_WINDOW_MS: suppress and count them.
//   When the next loggable request arrives: emit a summary entry for the
//   dropped requests first, then log the new one normally.
const BLOCKED_LOG_WINDOW_MS = 60_000; // 1-minute suppression window per IP

// Map<ip, { suppressUntil: number, droppedCount: number, lastEntry: object }>
const blockedIPLogTracker = new Map();

// Purge stale tracker entries periodically
const _blockedTrackerCleanup = setInterval(() => {
  const now = Date.now();
  for (const [ip, state] of blockedIPLogTracker.entries()) {
    if (now > state.suppressUntil + BLOCKED_LOG_WINDOW_MS * 5) {
      blockedIPLogTracker.delete(ip);
    }
  }
}, 5 * 60 * 1000);
if (_blockedTrackerCleanup.unref) _blockedTrackerCleanup.unref();

/**
 * Returns 0, 1, or 2 log entries to write for a blocked-IP hit.
 *  0 entries  => still inside suppression window, drop silently
 *  1 entry    => first hit or window just expired, write current entry
 *  2 entries  => window expired with suppressed hits: write summary then current
 */
function getBlockedIPLogEntries(ip, currentEntry) {
  const now = Date.now();
  const state = blockedIPLogTracker.get(ip);

  if (!state) {
    // First time we see this IP as blocked — log now, open suppression window
    blockedIPLogTracker.set(ip, { suppressUntil: now + BLOCKED_LOG_WINDOW_MS, droppedCount: 0, lastEntry: currentEntry });
    return [currentEntry];
  }

  if (now < state.suppressUntil) {
    // Inside suppression window — count the drop, write nothing
    state.droppedCount++;
    return [];
  }

  // Window expired — collect entries to write
  const entries = [];
  if (state.droppedCount > 0) {
    // Emit a single summary entry for all the suppressed requests
    const summaryEntry = {
      ...state.lastEntry,
      id: require("uuid").v4(),
      timestamp: new Date(state.suppressUntil).toISOString(),
      payload: `[Suppressed] ${state.droppedCount} additional blocked request${state.droppedCount !== 1 ? "s" : ""} from this IP were deduplicated in the previous 60s window`,
      ruleName: "IP Blocklist (suppressed summary)",
    };
    entries.push(summaryEntry);
  }
  entries.push(currentEntry);

  // Reset the window
  blockedIPLogTracker.set(ip, { suppressUntil: now + BLOCKED_LOG_WINDOW_MS, droppedCount: 0, lastEntry: currentEntry });
  return entries;
}

const wafMiddleware = async (req, res, next) => {
  
  const skipPaths = ["/health", "/api/dashboard", "/api/alerts", "/api/incidents", "/api/rules", "/api/reports", "/api/analytics", "/api/ip", "/api/admin", "/api/threat-map", "/api/auth"];
  if (skipPaths.some((p) => req.path.startsWith(p))) return next();
  totalRequestCount++;
  const ip = getRealIP(req);
  const deviceInfo = parseDeviceInfo(req.headers["user-agent"]);
  const deviceFingerprint = buildDeviceFingerprint(req);
  const countryData = await geoip.getCountry(ip);

  if (isWhitelisted(req, ip)) return next();

  // Also check the admin-managed whitelist from System Settings
  if (wafConfig.isWhitelistedBySettings(ip)) return next();

  if (store.blockedIPs.has(ip)) {
    const logEntry = buildLogEntry({ req, ip, countryData, deviceInfo, deviceFingerprint, attackType: "Other", severity: "high", action: "blocked", ruleId: "WAF-BLOCKLIST-001", ruleName: "IP Blocklist", matchedSIDs: "BLOCKLIST" });
    // Throttle logging: only write the first hit per 60-second window, then a
    // summary entry when the window expires. This prevents a hammering IP from
    // flooding the attack log with thousands of identical blocklist entries.
    const entriesToWrite = getBlockedIPLogEntries(ip, logEntry);
    for (const entry of entriesToWrite) {
      store.alerts.unshift(entry);
      db.insertAlert(entry).catch(err => console.error("DB alert write failed:", err.message));
    }
    if (store.alerts.length > 10000) store.alerts.splice(10000);
    return res.status(403).json({ error: "Forbidden: IP blocked by WAF" });
  }

  const snortMatches = matchSnortRules(req);
  const bestSnortMatch = snortMatches.length > 0 ? snortMatches[0] : null;

  // Read thresholds from DB rules so Rules page changes actually work.
  // getCachedRules() returns a 10-second cached copy so we don't hit the DB
  // on every single request when the simulator is running.
  const dbRules = await getCachedRules();

  // Per-rule thresholds from WAF Rules table, scaled by System Settings sensitivity
  const bfRule        = dbRules.find(r => r.category === "Brute Force");
  const ddosRule      = dbRules.find(r => r.category === "DDoS");
  const bfThreshold   = wafConfig.applyThreshold(bfRule?.threshold   || wafConfig.config.blockThreshold);
  const ddosThreshold = wafConfig.applyThreshold(ddosRule?.threshold || wafConfig.config.rateLimitRpm);

  let isBruteForce = false;
  let isBruteForceAttempt = false;
  const isLoginAttempt = req.method === "POST" && req.path.includes("/api/login");
  if (isLoginAttempt) { 
    isBruteForce = checkBruteForce(ip, bfThreshold);
    isBruteForceAttempt = !isBruteForce;
  }
  const isRateLimited = checkRateLimit(ip, ddosThreshold);

  let finalAttackType = bestSnortMatch ? bestSnortMatch.category : null;
  if (isBruteForce || isBruteForceAttempt) finalAttackType = "Brute Force";
  if (isRateLimited && !finalAttackType) finalAttackType = "DDoS";

  let severity = bestSnortMatch ? bestSnortMatch.effectiveSeverity : (store.SEVERITY_MAP[finalAttackType] || "info");
  const matchedRule = finalAttackType ? dbRules.find((r) => r.category === finalAttackType) : null;

  // ═══════════════════════════════════════════════════════════════════════════
  // NEW: Threshold-based blocking for ALL attack types
  // ═══════════════════════════════════════════════════════════════════════════
  let thresholdExceeded = false;
  if (finalAttackType && matchedRule && matchedRule.enabled && finalAttackType !== "Brute Force") {
    const attackThreshold = matchedRule.threshold || 1;
    thresholdExceeded = checkAttackThreshold(ip, finalAttackType, attackThreshold, 5);
  }


  let action = "allowed";
if (matchedRule) {
  if (!matchedRule.enabled) {
    action = "allowed"; // rule disabled — let through
  } else if (isBruteForce) {
    // checkBruteForce() already counted to threshold — block immediately
    action = matchedRule.action;
      } else if (isBruteForceAttempt) {
  action = "allowed";                 // ✅ below threshold → log as allowed
      }
    else if (isRateLimited) {
  // checkRateLimit() already handled the counting — block immediately
  action = matchedRule.action;
    }
  else {
    // ── Threshold gate ──────────────────────────────────────────
    // Check how many times this IP has triggered this attack type.
    // Only block once the threshold is reached — before that, log
    // it as "allowed" so the frontend shows the correct progression.
    // Threshold is scaled by the System Settings sensitivity level.
    const threshold = wafConfig.applyThreshold(matchedRule.threshold || wafConfig.config.blockThreshold);

    if (threshold <= 1) {
      // Threshold of 1 means block on first detection
      action = matchedRule.action;
    } else {
      // Increment counter for this IP + attack type
      const trackerKey = `${ip}::${finalAttackType}`;
      const now        = Date.now();
      const window     = 5 * 60 * 1000; // 5-minute rolling window

      let entry = store.attackThresholdTracker.get(trackerKey);
      if (!entry || (now - entry.firstSeen) > window) {
        // Fresh window — start counting from 1
        entry = { count: 1, firstSeen: now };
      } else {
        entry.count++;
      }
      store.attackThresholdTracker.set(trackerKey, entry);

      if (entry.count >= threshold) {
        action = matchedRule.action; // threshold met — apply rule action
      } else {
        action = "allowed"; // threshold not yet met — log but allow through
      }
    }
  }
} else if (bestSnortMatch && bestSnortMatch.shouldBlock) {
  action = "blocked"; // no DB rule, use snort fallback
}

  if (finalAttackType) {
    const logEntry = buildLogEntry({ req, ip, countryData, deviceInfo, deviceFingerprint, attackType: finalAttackType, severity, action, ruleId: matchedRule ? matchedRule.id : (bestSnortMatch ? `SID:${bestSnortMatch.sid}` : undefined), ruleName: matchedRule ? matchedRule.name : (bestSnortMatch ? bestSnortMatch.msg : undefined), matchedSIDs: snortMatches.length > 0 ? getMatchedSIDs(snortMatches) : undefined, snortMsg: bestSnortMatch ? bestSnortMatch.msg : undefined, falsePositiveScore: bestSnortMatch ? bestSnortMatch.falsePositiveScore : 0, cveReference: bestSnortMatch ? bestSnortMatch.reference : undefined });
    store.alerts.unshift(logEntry);
    db.insertAlert(logEntry).catch(err => console.error("DB alert write failed:", err.message));
    if (store.alerts.length > 10000) store.alerts.pop();
  }

  if (action === "blocked") {

       // ── FP tracking ──────────────────────────────────────────
      if (req.headers['x-sim-session-type'] === 'false-positive') {
        falsePositiveCount++;
      }

      if (severity === "critical" || isBruteForce || thresholdExceeded) {
        store.blockedIPs.add(ip);

        // Get attack count from tracker for logging
                let attackCount = 1;
                if (store.attackThresholdTracker.has(ip)) {
                  const ipTracker = store.attackThresholdTracker.get(ip);
                  const entry = ipTracker.get(finalAttackType);
                  attackCount = entry ? entry.count : 1;
                }

        // If block_duration_min > 0, schedule automatic unblock
        const durationMin = wafConfig.config.blockDurationMin;
        if (durationMin > 0) {
          setTimeout(() => {
            store.blockedIPs.delete(ip);
            db.pool.query("UPDATE waf_blocked_ips SET unblocked_at = NOW() WHERE ip_address = $1 AND unblocked_at IS NULL", [ip]).catch(() => {});
          }, durationMin * 60 * 1000);
        }

        // persist to PostgreSQL so block survives server restarts
        db.blockIP(ip, `Auto-blocked: ${finalAttackType}`, "waf-auto")
          .catch(err => console.error("DB blockIP failed:", err.message));
      }
      return res.status(403).json({ error: "Forbidden: Request blocked by WAF", rule: matchedRule ? matchedRule.name : "WAF Policy Violation"});
    }

  next();
};

function buildLogEntry({ req, ip, countryData, deviceInfo, deviceFingerprint, attackType, severity, action, ruleId, ruleName, matchedSIDs, snortMsg, falsePositiveScore, cveReference }) {
  return {
    id: uuidv4(),
    timestamp: new Date(),
    attackType,
    sourceIP: ip,
    targetURL: req.originalUrl,
    severity,
    action,
    country: countryData.country,
    countryCode: countryData.countryCode,
    latitude:    countryData.latitude  ?? null,   
    longitude:   countryData.longitude ?? null,
    requestMethod: req.method,
    userAgent: req.headers["user-agent"],
    ruleId,
    ruleName,
    matchedSIDs,
    snortMsg,
    falsePositiveScore: falsePositiveScore || 0,
    cveReference,
    device: { os: deviceInfo.os, browser: deviceInfo.browser, deviceType: deviceInfo.deviceType, isMaliciousTool: deviceInfo.isMaliciousTool, toolName: deviceInfo.toolName, fingerprint: deviceFingerprint },
    network: { forwardedFor: req.headers["x-forwarded-for"] || null, realIP: req.headers["x-real-ip"] || null, cfConnectingIP: req.headers["cf-connecting-ip"] || null, protocol: req.protocol, httpVersion: req.httpVersion },
    requestSize: parseInt(req.headers["content-length"] || "0"),
    contentType: req.headers["content-type"] || null,
    referer: req.headers["referer"] || null,
    acceptLanguage: req.headers["accept-language"] || null,
  };
}

module.exports = wafMiddleware;
module.exports.invalidateRulesCache = invalidateRulesCache;
module.exports.getRequestCount = () => ({        
  total: totalRequestCount,
  falsePositives: falsePositiveCount,
  since: new Date(countResetTime).toISOString(),
});