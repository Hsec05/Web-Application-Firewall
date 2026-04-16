/**
 * GeoIP Cache
 * Resolves real country + coordinates for IPs using ip-api.com (free, no API key).
 * Each unique IP is looked up ONCE and cached in memory forever for the
 * lifetime of the server process — no per-log queries.
 */

const axios = require("axios");

// In-memory cache: ip -> { country, countryCode, latitude, longitude }
const cache = new Map();

// IPs that should never be looked up
const PRIVATE_RANGES = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1)/;

const FALLBACK = { country: "Unknown", countryCode: "XX", latitude: null, longitude: null };

/**
 * Returns { country, countryCode, latitude, longitude } for a given IP.
 * - Private/loopback IPs return "Local Network" immediately.
 * - Already-cached IPs return instantly from memory.
 * - New IPs are looked up via ip-api.com and cached.
 */
async function getCountry(ip) {
  if (!ip || PRIVATE_RANGES.test(ip)) {
    return { country: "Local Network", countryCode: "LO", latitude: null, longitude: null };
  }

  if (cache.has(ip)) {
    return cache.get(ip);
  }

  try {
    // Request country, countryCode, lat, lon in one call — all free fields
    const res = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,lat,lon`,
      { timeout: 3000 }
    );
    if (res.data && res.data.status !== "fail") {
      const result = {
        country:     res.data.country     || "Unknown",
        countryCode: res.data.countryCode || "XX",
        latitude:    res.data.lat         ?? null,
        longitude:   res.data.lon         ?? null,
      };
      cache.set(ip, result);
      return result;
    }
  } catch {
    // network error or rate limit — fall through to fallback
  }

  // Cache the fallback too so we don't retry a dead IP repeatedly
  cache.set(ip, FALLBACK);
  return FALLBACK;
}

module.exports = { getCountry };
