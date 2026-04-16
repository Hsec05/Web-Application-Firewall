import { SecurityAlert } from '@/types/security';
import { SeverityBadge } from './SeverityBadge';
import { formatRelativeTime, getCountryFlag } from '@/lib/securityUtils';
import { cn } from '@/lib/utils';
import { Activity } from 'lucide-react';

interface LiveAlertsPanelProps {
  alerts: SecurityAlert[];
  onAlertClick?: (alert: SecurityAlert) => void;
  className?: string;
}

export function LiveAlertsPanel({ alerts, onAlertClick, className }: LiveAlertsPanelProps) {
  const recentAlerts = alerts.slice(0, 10);

  return (
    <div className={cn("soc-panel h-full flex flex-col", className)}>
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">
          <Activity className="h-4 w-4 text-severity-critical animate-pulse" />
          Live Attack Alerts
        </h3>
        <span className="text-xs text-muted-foreground font-mono">
          {alerts.length} total
        </span>
      </div>

      <div className="flex-1 overflow-y-auto soc-scrollbar space-y-2">
        {recentAlerts.map((alert, index) => (
          <div
            key={alert.id}
            onClick={() => onAlertClick?.(alert)}
            className={cn(
              "alert-item animate-fade-in",
              index === 0 && "border-l-2 border-l-severity-critical"
            )}
            style={{ animationDelay: `${index * 50}ms` }}
          >
            <div className="flex-shrink-0">
              <span className="text-lg">{getCountryFlag(alert.countryCode)}</span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-semibold text-sm truncate">{alert.attackType}</span>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="font-mono">{alert.sourceIP}</span>
                <span>→</span>
                <span className="truncate">{alert.targetURL}</span>
              </div>
            </div>
            <div className="text-xs text-muted-foreground whitespace-nowrap">
              {formatRelativeTime(alert.timestamp)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
