// Security Types for SOC Dashboard

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Action = 'blocked' | 'allowed';
export type AttackType = 'SQLi' | 'XSS' | 'Brute Force' | 'DDoS' | 'Path Traversal' | 'RCE' | 'CSRF' | 'XXE'| 'SSRF' | 'NoSQLi' | 'Open Redirect' | 'Prototype Pollution' | 'HTTP Smuggling' | 'Auth' | 'Recon' | 'Other';

export interface SecurityAlert {
  id: string;
  timestamp: Date;
  attackType: AttackType;
  sourceIP: string;
  targetURL: string;
  severity: Severity;
  action: Action;
  country: string;
  countryCode: string;
  requestMethod: string;
  userAgent?: string;
  payload?: string;
  ruleId?: string;
  ruleName?: string;
}

export interface IPProfile {
  ip: string;
  riskScore: number;
  country: string;
  countryCode: string;
  city?: string;
  isp?: string;
  isTor: boolean;
  isVPN: boolean;
  isProxy: boolean;
  totalRequests: number;
  blockedRequests: number;
  lastSeen: Date;
  firstSeen: Date;
  attackTypes: AttackType[];
  targetedURLs: string[];
}

export interface SecurityRule {
  id: string;
  name: string;
  category: AttackType;
  description: string;
  enabled: boolean;
  threshold: number;
  severity: Severity;
  action: Action;
  createdAt: Date;
  updatedAt: Date;
}

export interface Incident {
  id: string;
  title: string;
  timeRange: {
    start: Date;
    end: Date;
  };
  severity: Severity;
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  eventCount: number;
  affectedEndpoints: string[];
  relatedIPs: string[];
  events: SecurityAlert[];
  assignee?: string;
  notes?: string;
}

export interface DashboardMetrics {
  totalRequests: number;
  blockedRequests: number;
  uniqueAttackers: number;
  activeIncidents: number;
  topAttackTypes: { type: AttackType; count: number }[];
  topCountries: { country: string; countryCode: string; count: number }[];
  requestsOverTime: { time: string; total: number; blocked: number }[];
  severityDistribution: { severity: Severity; count: number }[];
}

export interface ReportConfig {
  type: 'daily' | 'weekly' | 'threats' | 'ips' | 'trends';
  dateRange: {
    start: Date;
    end: Date;
  };
  format: 'pdf' | 'csv' | 'json';
  includeCharts: boolean;
}
