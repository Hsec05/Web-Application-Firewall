import { cn } from '@/lib/utils';
import { getCountryFlag } from '@/lib/securityUtils';
import { Globe } from 'lucide-react';

interface CountryListProps {
  data: { country: string; countryCode: string; count: number }[];
  className?: string;
}

export function CountryList({ data, className }: CountryListProps) {
  const maxCount = Math.max(...data.map(d => d.count));

  return (
    <div className={cn("soc-panel h-full flex flex-col", className)}>
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">
          <Globe className="h-4 w-4 text-primary" />
          Top Attacking Countries
        </h3>
      </div>

      <div className="flex-1 overflow-y-auto soc-scrollbar space-y-2">
        {data.slice(0, 10).map((item, index) => (
          <div 
            key={item.countryCode}
            className="flex items-center gap-3 p-2 rounded-lg hover:bg-muted/30 transition-colors"
          >
            <span className="text-lg">{getCountryFlag(item.countryCode)}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium truncate">{item.country}</span>
                <span className="text-sm font-mono text-muted-foreground">
                  {item.count.toLocaleString()}
                </span>
              </div>
              <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                <div 
                  className={cn(
                    "h-full rounded-full transition-all duration-500",
                    index === 0 ? "bg-severity-critical" : 
                    index === 1 ? "bg-severity-high" :
                    index === 2 ? "bg-severity-medium" : "bg-primary"
                  )}
                  style={{ width: `${(item.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
