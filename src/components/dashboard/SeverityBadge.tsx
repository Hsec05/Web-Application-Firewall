import { cn } from '@/lib/utils';
import { Severity } from '@/types/security';
import { getSeverityColor, getSeverityBgColor, getSeverityBorderColor } from '@/lib/securityUtils';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span className={cn(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase border",
      getSeverityColor(severity),
      getSeverityBgColor(severity),
      getSeverityBorderColor(severity),
      className
    )}>
      {severity}
    </span>
  );
}
