import { cn } from '@/lib/utils';
import { Action } from '@/types/security';
import { getActionColor, getActionBgColor } from '@/lib/securityUtils';
import { ShieldX, ShieldCheck } from 'lucide-react';

interface ActionBadgeProps {
  action: Action;
  className?: string;
  showIcon?: boolean;
}

export function ActionBadge({ action, className, showIcon = true }: ActionBadgeProps) {
  const Icon = action === 'blocked' ? ShieldX : ShieldCheck;
  
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold uppercase border",
      getActionColor(action),
      getActionBgColor(action),
      action === 'blocked' ? 'border-status-blocked/30' : 'border-status-allowed/30',
      className
    )}>
      {showIcon && <Icon className="h-3 w-3" />}
      {action}
    </span>
  );
}
