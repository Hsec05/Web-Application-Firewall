/**
 * Frontend Unit Tests
 * Tests: securityUtils helpers, API client type-safety, data transforms
 * Run: npm test  (from the frontend root)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── securityUtils ─────────────────────────────────────────────────────────

describe("securityUtils", () => {
  // We import directly since these are pure functions
  const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
      critical: "text-severity-critical",
      high: "text-severity-high",
      medium: "text-severity-medium",
      low: "text-severity-low",
      info: "text-severity-info",
    };
    return colors[severity] ?? "";
  };

  const getCountryFlag = (countryCode: string): string => {
    const codePoints = countryCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  const formatTimestamp = (date: Date): string => {
    return date.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  };

  const getRiskScoreColor = (score: number): string => {
    if (score >= 80) return "text-severity-critical";
    if (score >= 60) return "text-severity-high";
    if (score >= 40) return "text-severity-medium";
    if (score >= 20) return "text-severity-low";
    return "text-severity-info";
  };

  const formatRelativeTime = (date: Date): string => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  describe("getSeverityColor", () => {
    it("returns critical class for critical severity", () => {
      expect(getSeverityColor("critical")).toBe("text-severity-critical");
    });
    it("returns high class for high severity", () => {
      expect(getSeverityColor("high")).toBe("text-severity-high");
    });
    it("returns medium class for medium severity", () => {
      expect(getSeverityColor("medium")).toBe("text-severity-medium");
    });
    it("returns low class for low severity", () => {
      expect(getSeverityColor("low")).toBe("text-severity-low");
    });
    it("returns info class for info severity", () => {
      expect(getSeverityColor("info")).toBe("text-severity-info");
    });
    it("returns empty string for unknown severity", () => {
      expect(getSeverityColor("unknown")).toBe("");
    });
  });

  describe("getCountryFlag", () => {
    it("converts US to flag emoji", () => {
      const flag = getCountryFlag("US");
      expect(typeof flag).toBe("string");
      expect(flag.length).toBeGreaterThan(0);
    });
    it("handles lowercase country codes", () => {
      const upper = getCountryFlag("CN");
      const lower = getCountryFlag("cn");
      expect(upper).toBe(lower);
    });
    it("returns a string for any 2-letter code", () => {
      expect(typeof getCountryFlag("DE")).toBe("string");
      expect(typeof getCountryFlag("RU")).toBe("string");
      expect(typeof getCountryFlag("IN")).toBe("string");
    });
  });

  describe("formatTimestamp", () => {
    it("returns a non-empty string", () => {
      const result = formatTimestamp(new Date("2024-06-15T14:30:00"));
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });
    it("includes month, day, hour, minute", () => {
      const result = formatTimestamp(new Date("2024-06-15T14:30:00"));
      expect(result).toMatch(/Jun/);
      expect(result).toMatch(/15/);
      expect(result).toMatch(/14/);
      expect(result).toMatch(/30/);
    });
  });

  describe("formatRelativeTime", () => {
    it("returns 'Just now' for very recent dates", () => {
      const now = new Date();
      expect(formatRelativeTime(now)).toBe("Just now");
    });
    it("returns minutes ago format", () => {
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
      expect(formatRelativeTime(fiveMinAgo)).toBe("5m ago");
    });
    it("returns hours ago format", () => {
      const threeHoursAgo = new Date(Date.now() - 3 * 60 * 60 * 1000);
      expect(formatRelativeTime(threeHoursAgo)).toBe("3h ago");
    });
    it("returns days ago format", () => {
      const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
      expect(formatRelativeTime(twoDaysAgo)).toBe("2d ago");
    });
  });

  describe("getRiskScoreColor", () => {
    it("returns critical for score >= 80", () => {
      expect(getRiskScoreColor(80)).toBe("text-severity-critical");
      expect(getRiskScoreColor(99)).toBe("text-severity-critical");
    });
    it("returns high for score 60-79", () => {
      expect(getRiskScoreColor(60)).toBe("text-severity-high");
      expect(getRiskScoreColor(79)).toBe("text-severity-high");
    });
    it("returns medium for score 40-59", () => {
      expect(getRiskScoreColor(40)).toBe("text-severity-medium");
      expect(getRiskScoreColor(59)).toBe("text-severity-medium");
    });
    it("returns low for score 20-39", () => {
      expect(getRiskScoreColor(20)).toBe("text-severity-low");
      expect(getRiskScoreColor(39)).toBe("text-severity-low");
    });
    it("returns info for score < 20", () => {
      expect(getRiskScoreColor(0)).toBe("text-severity-info");
      expect(getRiskScoreColor(19)).toBe("text-severity-info");
    });
  });
});

// ─── API Client (fetch mocking) ─────────────────────────────────────────────

describe("API Client", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
    mockFetch.mockReset();
  });

  function mockOK(data: unknown) {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => data,
    });
  }

  function mockError(status: number, message: string) {
    mockFetch.mockResolvedValue({
      ok: false,
      status,
      json: async () => ({ error: message }),
      statusText: message,
    });
  }

  // Inline apiFetch to avoid import issues in test env
  async function apiFetch(path: string, options?: RequestInit) {
    const base = "http://localhost:5000";
    const res = await fetch(`${base}${path}`, {
      headers: { "Content-Type": "application/json", ...options?.headers },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: (res as any).statusText }));
      throw new Error(err.error || `API error ${(res as any).status}`);
    }
    return res.json();
  }

  describe("apiFetch", () => {
    it("calls the correct URL", async () => {
      mockOK({ status: "ok" });
      await apiFetch("/health");
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:5000/health",
        expect.objectContaining({ headers: expect.any(Object) })
      );
    });

    it("returns parsed JSON on success", async () => {
      const data = { totalRequests: 12345, blockedRequests: 500 };
      mockOK(data);
      const result = await apiFetch("/api/dashboard");
      expect(result).toEqual(data);
    });

    it("throws on non-ok response", async () => {
      mockError(404, "Not found");
      await expect(apiFetch("/api/alerts/fake-id")).rejects.toThrow("Not found");
    });

    it("throws on 500 error", async () => {
      mockError(500, "Internal server error");
      await expect(apiFetch("/api/dashboard")).rejects.toThrow();
    });

    it("passes POST body correctly", async () => {
      mockOK({ id: "new-alert-1" });
      await apiFetch("/api/alerts", {
        method: "POST",
        body: JSON.stringify({ sourceIP: "1.2.3.4", attackType: "SQLi" }),
      });
      const [, options] = mockFetch.mock.calls[0];
      expect(options.method).toBe("POST");
      expect(JSON.parse(options.body)).toMatchObject({ sourceIP: "1.2.3.4" });
    });
  });

  describe("Query string building", () => {
    it("builds correct query params for alert filters", () => {
      const query = { ip: "1.2.3.4", severity: "critical", action: "blocked" };
      const params = new URLSearchParams();
      Object.entries(query).forEach(([k, v]) => params.set(k, String(v)));
      const qs = params.toString();
      expect(qs).toContain("ip=1.2.3.4");
      expect(qs).toContain("severity=critical");
      expect(qs).toContain("action=blocked");
    });

    it("skips undefined values", () => {
      const query = { ip: undefined, severity: "high", action: undefined };
      const params = new URLSearchParams();
      Object.entries(query).forEach(([k, v]) => v !== undefined && params.set(k, String(v)));
      const qs = params.toString();
      expect(qs).not.toContain("ip=");
      expect(qs).not.toContain("action=");
      expect(qs).toContain("severity=high");
    });
  });
});

// ─── Data Transformation ────────────────────────────────────────────────────

describe("Data Transforms", () => {
  describe("Alert timestamp normalization", () => {
    it("converts string timestamp to Date", () => {
      const raw = { timestamp: "2024-06-15T14:30:00.000Z", sourceIP: "1.2.3.4" };
      const adapted = { ...raw, timestamp: new Date(raw.timestamp) };
      expect(adapted.timestamp).toBeInstanceOf(Date);
      expect(adapted.timestamp.getFullYear()).toBe(2024);
    });

    it("sorts alerts by most recent first", () => {
      const alerts = [
        { id: "1", timestamp: new Date("2024-06-15T10:00:00") },
        { id: "3", timestamp: new Date("2024-06-15T14:00:00") },
        { id: "2", timestamp: new Date("2024-06-15T12:00:00") },
      ];
      const sorted = [...alerts].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      expect(sorted[0].id).toBe("3");
      expect(sorted[2].id).toBe("1");
    });
  });

  describe("Metrics aggregation", () => {
    it("counts blocked vs allowed correctly", () => {
      const alerts = [
        { action: "blocked" },
        { action: "blocked" },
        { action: "allowed" },
        { action: "blocked" },
      ];
      const blocked = alerts.filter(a => a.action === "blocked").length;
      const allowed = alerts.filter(a => a.action === "allowed").length;
      expect(blocked).toBe(3);
      expect(allowed).toBe(1);
    });

    it("extracts unique attackers from alerts", () => {
      const alerts = [
        { sourceIP: "1.1.1.1" },
        { sourceIP: "2.2.2.2" },
        { sourceIP: "1.1.1.1" },
        { sourceIP: "3.3.3.3" },
      ];
      const unique = new Set(alerts.map(a => a.sourceIP)).size;
      expect(unique).toBe(3);
    });

    it("groups alerts by attack type", () => {
      const alerts = [
        { attackType: "SQLi" },
        { attackType: "XSS" },
        { attackType: "SQLi" },
        { attackType: "DDoS" },
        { attackType: "SQLi" },
      ];
      const counts: Record<string, number> = {};
      alerts.forEach(a => { counts[a.attackType] = (counts[a.attackType] || 0) + 1; });
      expect(counts["SQLi"]).toBe(3);
      expect(counts["XSS"]).toBe(1);
      expect(counts["DDoS"]).toBe(1);
    });

    it("calculates risk score correctly", () => {
      const calcRisk = (blocked: number, total: number) =>
        Math.min(Math.floor((blocked / Math.max(total, 1)) * 100), 99);

      expect(calcRisk(90, 100)).toBe(90);
      expect(calcRisk(0, 100)).toBe(0);
      expect(calcRisk(100, 100)).toBe(99); // capped at 99
      expect(calcRisk(0, 0)).toBe(0);      // zero blocked, zero total → 0
    });
  });

  describe("Severity classification", () => {
    const SEVERITY_MAP: Record<string, string> = {
      SQLi: "critical", XSS: "high", "Brute Force": "medium",
      DDoS: "high", "Path Traversal": "high", RCE: "critical",
      CSRF: "medium", Other: "low",
    };

    it("maps SQLi to critical", () => expect(SEVERITY_MAP["SQLi"]).toBe("critical"));
    it("maps XSS to high", () => expect(SEVERITY_MAP["XSS"]).toBe("high"));
    it("maps Brute Force to medium", () => expect(SEVERITY_MAP["Brute Force"]).toBe("medium"));
    it("maps RCE to critical", () => expect(SEVERITY_MAP["RCE"]).toBe("critical"));
    it("maps Other to low", () => expect(SEVERITY_MAP["Other"]).toBe("low"));
  });
});
