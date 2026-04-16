import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { lookupIP, blockIP, unblockIP, type IPLookupResponse } from '@/lib/api';
import {
  Search, Globe, Shield, AlertTriangle, Activity,
  Clock, Server, ShieldOff, Eye, Wifi, Lock, RefreshCw
} from 'lucide-react';
import { getCountryFlag, formatTimestamp, getRiskScoreColor } from '@/lib/securityUtils';
import { cn } from '@/lib/utils';

const IPIntelligence = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [searchInput, setSearchInput] = useState(searchParams.get('ip') || '');
  const [ipData, setIpData] = useState<IPLookupResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [blocking, setBlocking] = useState(false);

  // Auto-search if IP is in URL params
  useEffect(() => {
    const ip = searchParams.get('ip');
    if (ip) {
      setSearchInput(ip);
      handleSearch(ip);
    }
  }, []);

  const handleSearch = async (ip?: string) => {
    const query = ip || searchInput;
    if (!query.trim()) return;

    setLoading(true);
    setError('');
    setIpData(null);

    try {
      const data = await lookupIP(query.trim());
      setIpData(data);
      setSearchParams({ ip: query.trim() });
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Failed to fetch IP data. Make sure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleBlockToggle = async () => {
    if (!ipData) return;
    setBlocking(true);
    try {
      if (ipData.isBlockedLocally) {
        await unblockIP(ipData.ip);
        setIpData({ ...ipData, isBlockedLocally: false });
      } else {
        await blockIP(ipData.ip);
        setIpData({ ...ipData, isBlockedLocally: true });
      }
    } catch (err) {
      console.error('Block/unblock failed:', err);
    } finally {
      setBlocking(false);
    }
  };

  const riskColor = ipData
    ? ipData.abuseConfidenceScore >= 80 ? 'border-red-500 text-red-500'
    : ipData.abuseConfidenceScore >= 50 ? 'border-orange-500 text-orange-500'
    : ipData.abuseConfidenceScore >= 20 ? 'border-yellow-500 text-yellow-500'
    : 'border-green-500 text-green-500'
    : '';

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold">IP Intelligence</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Investigate IP addresses using AbuseIPDB + local WAF history
          </p>
        </div>

        {/* Search */}
        <div className="soc-panel">
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Enter IP address (e.g. 8.8.8.8)"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                className="pl-10 font-mono bg-muted/50"
              />
            </div>
            <Button onClick={() => handleSearch()} disabled={loading}>
              {loading
                ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Looking up...</>
                : <><Globe className="h-4 w-4 mr-2" />Lookup</>
              }
            </Button>
          </div>
          {error && (
            <p className="text-red-500 text-sm mt-3 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {error}
            </p>
          )}
        </div>

        {/* Results */}
        {ipData && (
          <div className="space-y-6">

            {/* API Source Warning */}
            {ipData.warning && (
              <div className="soc-panel bg-yellow-500/5 border-yellow-500/30 flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-yellow-500">Limited Data</p>
                  <p className="text-xs text-muted-foreground mt-1">{ipData.warning}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Get a free API key at{' '}
                    <a href="https://www.abuseipdb.com/register" target="_blank" rel="noreferrer" className="text-primary underline">
                      abuseipdb.com/register
                    </a>{' '}
                    and add it to <code className="bg-muted px-1 rounded">soc-backend/.env</code> as <code className="bg-muted px-1 rounded">ABUSEIPDB_API_KEY</code>
                  </p>
                </div>
              </div>
            )}

            {/* IP Header */}
            <div className="soc-panel flex justify-between items-start flex-wrap gap-4">
              <div>
                <h2 className="text-2xl font-mono font-bold">{ipData.ip}</h2>
                <div className="flex items-center gap-2 mt-2 text-muted-foreground flex-wrap">
                  {ipData.countryCode && (
                    <span className="text-2xl">{getCountryFlag(ipData.countryCode)}</span>
                  )}
                  {ipData.countryName && <span>{ipData.countryName}</span>}
                  {ipData.isp && (
                    <span className="text-xs bg-muted px-2 py-0.5 rounded">
                      {ipData.isp}
                    </span>
                  )}
                </div>

                {/* Flags */}
                <div className="flex items-center gap-2 mt-3 flex-wrap">
                  {ipData.isTor && (
                    <Badge variant="destructive" className="text-xs">
                      <Eye className="h-3 w-3 mr-1" />TOR Exit Node
                    </Badge>
                  )}
                  {ipData.isVPN && (
                    <Badge variant="outline" className="text-xs border-orange-500/50 text-orange-500">
                      <Lock className="h-3 w-3 mr-1" />VPN
                    </Badge>
                  )}
                  {ipData.isProxy && (
                    <Badge variant="outline" className="text-xs border-yellow-500/50 text-yellow-500">
                      <Wifi className="h-3 w-3 mr-1" />Proxy
                    </Badge>
                  )}
                  {ipData.isBlockedLocally && (
                    <Badge variant="outline" className="text-xs border-red-500/50 text-red-500">
                      <ShieldOff className="h-3 w-3 mr-1" />Blocked by WAF
                    </Badge>
                  )}
                  {ipData.source && (
                    <Badge variant="secondary" className="text-xs">
                      Source: {ipData.source}
                    </Badge>
                  )}
                </div>
              </div>

              <div className="flex flex-col items-center gap-3">
                {/* Risk Score Ring */}
                <div className={cn("w-24 h-24 rounded-full border-4 flex items-center justify-center", riskColor)}>
                  <div className="text-center">
                    <div className="text-2xl font-bold">{ipData.abuseConfidenceScore}</div>
                    <div className="text-xs opacity-70">/ 100</div>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground">Abuse Score</span>

                {/* Block Button */}
                <Button
                  size="sm"
                  variant={ipData.isBlockedLocally ? "outline" : "destructive"}
                  onClick={handleBlockToggle}
                  disabled={blocking}
                  className="w-full"
                >
                  {blocking
                    ? <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                    : <ShieldOff className="h-3 w-3 mr-1" />
                  }
                  {ipData.isBlockedLocally ? 'Unblock IP' : 'Block IP'}
                </Button>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="soc-panel text-center">
                <Activity className="mx-auto mb-2 text-primary" />
                <div className="text-2xl font-bold">{ipData.totalReports ?? 0}</div>
                <div className="text-xs text-muted-foreground">AbuseIPDB Reports</div>
              </div>

              <div className="soc-panel text-center">
                <Shield className="mx-auto mb-2 text-red-500" />
                <div className="text-2xl font-bold text-red-500">{ipData.blockedLocally ?? 0}</div>
                <div className="text-xs text-muted-foreground">Blocked by our WAF</div>
              </div>

              <div className="soc-panel text-center">
                <Clock className="mx-auto mb-2" />
                <div className="text-sm font-medium">
                  {ipData.lastReportedAt
                    ? formatTimestamp(new Date(ipData.lastReportedAt))
                    : ipData.lastSeenLocally
                    ? formatTimestamp(new Date(ipData.lastSeenLocally))
                    : 'Never'}
                </div>
                <div className="text-xs text-muted-foreground">Last Seen</div>
              </div>

              <div className="soc-panel text-center">
                <Server className="mx-auto mb-2" />
                <div className="text-sm font-medium truncate">{ipData.isp || 'Unknown'}</div>
                <div className="text-xs text-muted-foreground">ISP / Host</div>
              </div>
            </div>

            {/* Two column: Local WAF + Attack Categories */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

              {/* Local WAF Activity */}
              <div className="soc-panel space-y-4">
                <h3 className="font-semibold flex items-center gap-2">
                  <Shield className="h-4 w-4 text-primary" />
                  Local WAF Activity
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Total Requests Hit WAF</span>
                    <span className="font-mono font-bold">{ipData.totalLocalRequests}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Blocked by WAF</span>
                    <span className="font-mono font-bold text-red-500">{ipData.blockedLocally}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">First Seen</span>
                    <span className="font-mono text-xs">
                      {ipData.firstSeenLocally
                        ? formatTimestamp(new Date(ipData.firstSeenLocally))
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Last Seen</span>
                    <span className="font-mono text-xs">
                      {ipData.lastSeenLocally
                        ? formatTimestamp(new Date(ipData.lastSeenLocally))
                        : 'N/A'}
                    </span>
                  </div>
                  {ipData.targetedURLs?.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Targeted URLs</p>
                      <div className="flex flex-wrap gap-1">
                        {ipData.targetedURLs.map((url) => (
                          <Badge key={url} variant="secondary" className="font-mono text-xs">{url}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Attack Categories */}
              <div className="soc-panel space-y-4">
                <h3 className="font-semibold flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  Attack Categories
                </h3>
                {(ipData.categories?.length > 0 || ipData.attackTypesLocally?.length > 0) ? (
                  <div className="space-y-3">
                    {ipData.categories?.length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-2">From AbuseIPDB</p>
                        <div className="flex flex-wrap gap-2">
                          {ipData.categories.map((cat, i) => (
                            <Badge key={i} variant="destructive" className="text-xs">{cat}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {ipData.attackTypesLocally?.length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-2">Detected by our WAF</p>
                        <div className="flex flex-wrap gap-2">
                          {ipData.attackTypesLocally.map((type, i) => (
                            <Badge key={i} variant="outline" className="text-xs border-primary/40 text-primary">{type}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No attack categories recorded for this IP.</p>
                )}
              </div>
            </div>

          </div>
        )}

        {/* Empty state */}
        {!ipData && !loading && (
          <div className="soc-panel h-[300px] flex items-center justify-center">
            <div className="text-center text-muted-foreground">
              <Globe className="h-12 w-12 mx-auto mb-4 opacity-20" />
              <p className="text-sm">Enter an IP address to view intelligence data</p>
              <p className="text-xs mt-2 opacity-60">Try: 8.8.8.8 · 1.1.1.1 · 185.220.101.1</p>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default IPIntelligence;
