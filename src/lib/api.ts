/**
 * Centralized API client for the SOC Dashboard backend.
 * All mock data has been replaced with real API calls.
 */

const API_BASE = "";

// Read the JWT from sessionStorage (same key used by AuthContext)
function getStoredToken(): string | null {
  try { return sessionStorage.getItem("soc_jwt_token"); } catch { return null; }
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const authHeader: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...authHeader, ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || `API error ${res.status}`);
  }
  return res.json();
}

// ── Dashboard ──────────────────────────────────────────────────────────────

export const getDashboardMetrics = () => apiFetch<DashboardMetricsResponse>("/api/dashboard");

// ── Alerts ─────────────────────────────────────────────────────────────────

export interface AlertsQuery {
  ip?: string;
  severity?: string;
  attackType?: string;
  action?: string;
  from?: string;
  to?: string;
  page?: number;
  limit?: number;
}

export const getAlerts = (query: AlertsQuery = {}) => {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => v !== undefined && params.set(k, String(v)));
  const qs = params.toString();
  return apiFetch<AlertsResponse>(`/api/alerts${qs ? `?${qs}` : ""}`);
};

export const getLiveAlerts = () => apiFetch<AlertItem[]>("/api/alerts/live");

// ── IP Intelligence ────────────────────────────────────────────────────────

export const lookupIP = (ip: string) => apiFetch<IPLookupResponse>(`/api/ip/${encodeURIComponent(ip)}`);

export const blockIP = (ip: string) =>
  apiFetch("/api/ip/block", { method: "POST", body: JSON.stringify({ ip }) });

export const unblockIP = (ip: string) =>
  apiFetch(`/api/ip/block/${encodeURIComponent(ip)}`, { method: "DELETE" });

// ── Incidents ──────────────────────────────────────────────────────────────

export const getIncidents = (query: { status?: string; severity?: string } = {}) => {
  const params = new URLSearchParams(query as Record<string, string>);
  return apiFetch<IncidentsResponse>(`/api/incidents?${params}`);
};

export const getIncident = (id: string) => apiFetch<IncidentItem>(`/api/incidents/${id}`);

export const updateIncident = (id: string, data: Partial<IncidentItem>) =>
  apiFetch<IncidentItem>(`/api/incidents/${id}`, { method: "PATCH", body: JSON.stringify(data) });

// ── Rules ──────────────────────────────────────────────────────────────────

export const getRules = () => apiFetch<RulesResponse>("/api/rules");

export const toggleRule = (id: string) =>
  apiFetch<SecurityRule>(`/api/rules/${id}/toggle`, { method: "POST" });

export const updateRule = (id: string, data: Partial<SecurityRule>) =>
  apiFetch<SecurityRule>(`/api/rules/${id}`, { method: "PATCH", body: JSON.stringify(data) });

// ── Analytics ──────────────────────────────────────────────────────────────

export const getAnalytics = (query: { from?: string; to?: string } = {}) => {
  const params = new URLSearchParams(query as Record<string, string>);
  return apiFetch<AnalyticsResponse>(`/api/analytics?${params}`);
};

// ── Reports ────────────────────────────────────────────────────────────────

export const generateReport = (body: ReportRequest) =>
  apiFetch<ReportResponse>("/api/reports/generate", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const getReportPreview = (query: { type?: string; from?: string; to?: string } = {}) => {
  const params = new URLSearchParams(query as Record<string, string>);
  return apiFetch<ReportPreview>(`/api/reports/preview?${params}`);
};

export const getThreatMapEvents = (
  query: { minutes?: number; limit?: number; action?: string } = {}
) => {
  const params = new URLSearchParams();
  if (query.minutes) params.set("minutes", String(query.minutes));
  if (query.limit)   params.set("limit",   String(query.limit));
  if (query.action)  params.set("action",  query.action);
  const qs = params.toString();
  return apiFetch<ThreatMapEventsResponse>(`/api/threat-map${qs ? `?${qs}` : ""}`);
};

// ── Threat Map ────────────────────────────────────────────────────────────────

export const getThreatMapSummary = (
  query: { minutes?: number } = {}
) => {
  const params = new URLSearchParams();
  if (query.minutes) params.set("minutes", String(query.minutes));
  const qs = params.toString();
  return apiFetch<ThreatMapSummaryResponse>(`/api/threat-map/summary${qs ? `?${qs}` : ""}`);
};

// ── Audit Logs ─────────────────────────────────────────────────────────────

export interface AuditLogEntry {
  id:         number;
  timestamp:  string;
  username:   string;
  role:       string;
  action:     string;
  category:   string;
  target:     string | null;
  target_id:  string | null;
  detail:     Record<string, unknown> | null;
  ip_address: string | null;
  outcome:    "success" | "failure";
}

export interface AuditLogsResponse {
  data:  AuditLogEntry[];
  total: number;
  page:  number;
  limit: number;
  pages: number;
  stats: { success_count: string; failure_count: string; unique_users: string; last_24h: string };
}

export const getAuditLogs = (query: {
  page?: number; limit?: number; username?: string;
  action?: string; category?: string; outcome?: string; from?: string; to?: string;
} = {}, token: string) => {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => v !== undefined && params.set(k, String(v)));
  return apiFetch<AuditLogsResponse>(`/api/audit-logs?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
};

// ── System Settings ────────────────────────────────────────────────────────

export const getSettings = (token: string, category?: string) => {
  const qs = category ? `?category=${category}` : "";
  return apiFetch<{ settings: Record<string, Record<string, unknown>>; flat: unknown[] }>(`/api/settings${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
};

export const updateSettings = (updates: Record<string, unknown>, token: string) =>
  apiFetch("/api/settings", {
    method: "PATCH",
    body: JSON.stringify({ updates }),
    headers: { Authorization: `Bearer ${token}` },
  });

// ── User Management ────────────────────────────────────────────────────────

export interface SocUser {
  id:         number;
  username:   string;
  email:      string;
  role:       "admin" | "analyst" | "viewer";
  is_active:  boolean;
  last_login: string | null;
  created_at: string;
  updated_at: string;
}

export const getUsers = (token: string) =>
  apiFetch<{ data: SocUser[]; total: number }>("/api/users", {
    headers: { Authorization: `Bearer ${token}` },
  });

export const updateUser = (id: number, data: { role?: string; is_active?: boolean }, token: string) =>
  apiFetch<SocUser>(`/api/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
    headers: { Authorization: `Bearer ${token}` },
  });

export const deleteUser = (id: number, token: string) =>
  apiFetch(`/api/users/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });

// ── Type Definitions ───────────────────────────────────────────────────────

export interface AlertItem {
  id: string;
  timestamp: string;
  attackType: string;
  sourceIP: string;
  targetURL: string;
  severity: string;
  action: string;
  country: string;
  countryCode: string;
  requestMethod: string;
  userAgent?: string;
  payload?: string;
  ruleId?: string;
  ruleName?: string;
}

export interface AlertsResponse {
  data: AlertItem[];
  total: number;
  page: number;
  limit: number;
  pages: number;
}

export interface IPLookupResponse {
  ip: string;
  source: string;
  warning?: string;
  abuseConfidenceScore: number;
  countryCode?: string;
  countryName?: string;
  city?: string;
  isp?: string;
  isTor: boolean;
  isVPN: boolean;
  isProxy: boolean;
  totalReports: number;
  lastReportedAt?: string;
  categories: string[];
  totalLocalRequests: number;
  blockedLocally: number;
  firstSeenLocally?: string;
  lastSeenLocally?: string;
  attackTypesLocally: string[];
  targetedURLs: string[];
  isBlockedLocally: boolean;
}

export interface IncidentItem {
  id: string;
  title: string;
  timeRange: { start: string; end: string };
  severity: string;
  status: "open" | "investigating" | "resolved" | "closed";
  eventCount: number;
  affectedEndpoints: string[];
  relatedIPs: string[];
  events: AlertItem[];
  assignee?: string;
  notes?: string;
}

export interface IncidentsResponse {
  data: IncidentItem[];
  total: number;
  summary: Record<string, number>;
}

export interface SecurityRule {
  id: string;
  name: string;
  category: string;
  description: string;
  enabled: boolean;
  threshold: number;
  severity: string;
  action: string;
  createdAt: string;
  updatedAt: string;
}

export interface RulesResponse {
  data: SecurityRule[];
  total: number;
  active: number;
}

export interface DashboardMetricsResponse {
  totalRequests: number;
  blockedRequests: number;
  uniqueAttackers: number;
  activeIncidents: number;
  topAttackTypes: { type: string; count: number }[];
  topCountries: { country: string; countryCode: string; count: number }[];
  requestsOverTime: { time: string; total: number; blocked: number }[];
  severityDistribution: { severity: string; count: number }[];
  topAttackingIPs: {
    ip: string;
    country: string;
    countryCode: string;
    count: number;
    blockedRequests: number;
    attackTypes: string[];
    riskScore: number;
  }[];
}

export interface AnalyticsResponse {
  topURLs: { url: string; count: number }[];
  hourlyData: { hour: string; attacks: number; blocked: number }[];
  topAttackingIPs: {
    ip: string;
    count: number;
    country: string;
    countryCode: string;
    attackTypes: string[];
    blocked: number;
    riskScore: number;
  }[];
  attackTypeBreakdown: { type: string; count: number; blocked: number }[];
  severityDistribution: { severity: string; count: number }[];
  methodDistribution: { method: string; count: number }[];
  totalAnalyzed: number;
}

export interface ReportRequest {
  type: "daily" | "weekly" | "threats" | "ips" | "trends";
  dateRange: { start: string; end: string };
  format: "json" | "csv";
}

export interface ReportResponse {
  reportType: string;
  generatedAt: string;
  dateRange: { from: string; to: string };
  [key: string]: unknown;
}

export interface ReportPreview {
  totalEvents: number;
  uniqueIPs: number;
  blockedThreats: number;
  criticalAlerts: number;
  dateRange: { from: string; to: string };
}

export interface ThreatMapEvent {
  id:          string;
  timestamp:   string;
  attackType:  string;
  sourceIP:    string;
  targetURL:   string;
  severity:    string;
  action:      string;
  country:     string;
  countryCode: string;
  latitude:    number;
  longitude:   number;
  ruleName?:   string;
}

export interface ThreatMapCountry {
  country:     string;
  countryCode: string;
  latitude:    number;
  longitude:   number;
  total:       number;
  blocked:     number;
  critical:    number;
  high:        number;
  attackTypes: string[];
}

export interface ThreatMapEventsResponse {
  events:  ThreatMapEvent[];
  total:   number;
  minutes: number;
}

export interface ThreatMapSummaryResponse {
  countries: ThreatMapCountry[];
  minutes:   number;
}
