import { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: {
    value: number;
    trend: 'up' | 'down';
  };
  icon?: LucideIcon;
  iconColor?: string;
  className?: string;
  children?: ReactNode;
}

export function MetricCard({ 
  title, 
  value, 
  change, 
  icon: Icon, 
  iconColor = 'text-primary',
  className,
  children 
}: MetricCardProps) {
  return (
    <div className={cn("soc-panel hover:border-primary/30 transition-all duration-300", className)}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
            {title}
          </p>
          <p className="text-3xl font-bold font-mono mt-2 animate-count-up">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          {change && (
            <div className="flex items-center gap-1 mt-2">
              <span className={cn(
                "text-xs font-medium",
                change.trend === 'up' ? 'text-severity-high' : 'text-severity-safe'
              )}>
                {change.trend === 'up' ? '↑' : '↓'} {Math.abs(change.value)}%
              </span>
              <span className="text-xs text-muted-foreground">vs last hour</span>
            </div>
          )}
        </div>
        {Icon && (
          <div className={cn("p-3 rounded-lg bg-muted/50", iconColor)}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
      {children}
    </div>
  );
}
