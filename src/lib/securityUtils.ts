import { Severity, Action } from '@/types/security';

export const getSeverityColor = (severity: Severity): string => {
  const colors = {
    critical: 'text-severity-critical',
    high: 'text-severity-high',
    medium: 'text-severity-medium',
    low: 'text-severity-low',
    info: 'text-severity-info',
  };
  return colors[severity];
};

export const getSeverityBgColor = (severity: Severity): string => {
  const colors = {
    critical: 'bg-severity-critical/20',
    high: 'bg-severity-high/20',
    medium: 'bg-severity-medium/20',
    low: 'bg-severity-low/20',
    info: 'bg-severity-info/20',
  };
  return colors[severity];
};

export const getSeverityBorderColor = (severity: Severity): string => {
  const colors = {
    critical: 'border-severity-critical/30',
    high: 'border-severity-high/30',
    medium: 'border-severity-medium/30',
    low: 'border-severity-low/30',
    info: 'border-severity-info/30',
  };
  return colors[severity];
};

export const getActionColor = (action: Action): string => {
  return action === 'blocked' ? 'text-status-blocked' : 'text-status-allowed';
};

export const getActionBgColor = (action: Action): string => {
  return action === 'blocked' ? 'bg-status-blocked/20' : 'bg-status-allowed/20';
};

export const formatTimestamp = (date: Date): string => {
  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
};

export const formatRelativeTime = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
};

export const getRiskScoreColor = (score: number): string => {
  if (score >= 80) return 'text-severity-critical';
  if (score >= 60) return 'text-severity-high';
  if (score >= 40) return 'text-severity-medium';
  if (score >= 20) return 'text-severity-low';
  return 'text-severity-info';
};

export const getRiskScoreBg = (score: number): string => {
  if (score >= 80) return 'bg-severity-critical';
  if (score >= 60) return 'bg-severity-high';
  if (score >= 40) return 'bg-severity-medium';
  if (score >= 20) return 'bg-severity-low';
  return 'bg-severity-info';
};

export const getCountryFlag = (countryCode: string | null | undefined): string => {
  if (!countryCode) return '🌐';
  // Convert country code to flag emoji
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};
