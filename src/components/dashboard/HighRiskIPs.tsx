import { cn } from '@/lib/utils';
import { IPProfile } from '@/types/security';
import { getRiskScoreColor, getRiskScoreBg, getCountryFlag } from '@/lib/securityUtils';
import { AlertTriangle, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';

interface HighRiskIPsProps {
  profiles: IPProfile[];
  className?: string;
}

export function HighRiskIPs({ profiles, className }: HighRiskIPsProps) {
  const highRiskProfiles = profiles.filter(p => p.riskScore >= 60).slice(0, 5);

  return (
    <div className={cn("soc-panel h-full flex flex-col", className)}>
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">
          <AlertTriangle className="h-4 w-4 text-severity-high" />
          High-Risk IP Activity
        </h3>
        <Link 
          to="/ip-intel" 
          className="text-xs text-primary hover:text-primary/80 flex items-center gap-1"
        >
          View All <ExternalLink className="h-3 w-3" />
        </Link>
      </div>

      <div className="flex-1 overflow-y-auto soc-scrollbar">
        <table className="soc-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Risk</th>
              <th>Country</th>
              <th>Blocked</th>
            </tr>
          </thead>
          <tbody>
            {highRiskProfiles.map((profile) => (
              <tr key={profile.ip}>
                <td>
                  <Link 
                    to={`/ip-intel?ip=${profile.ip}`}
                    className="hover:text-primary transition-colors"
                  >
                    {profile.ip}
                  </Link>
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <div 
                      className={cn(
                        "w-8 h-2 rounded-full",
                        getRiskScoreBg(profile.riskScore)
                      )}
                    />
                    <span className={cn("font-semibold", getRiskScoreColor(profile.riskScore))}>
                      {profile.riskScore}
                    </span>
                  </div>
                </td>
                <td>
                  <span className="flex items-center gap-1">
                    {getCountryFlag(profile.countryCode ?? '')}
                    <span className="text-muted-foreground">{profile.countryCode}</span>
                  </span>
                </td>
                <td>
                  <span className="text-status-blocked font-semibold">
                    {profile.blockedRequests.toLocaleString()}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
