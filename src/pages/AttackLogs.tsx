import { useState, useEffect, useMemo } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { SeverityBadge } from '@/components/dashboard/SeverityBadge';
import { ActionBadge } from '@/components/dashboard/ActionBadge';
import { getAlerts, type AlertItem } from '@/lib/api';
import { Severity, AttackType, Action } from '@/types/security';
import { formatTimestamp, getCountryFlag } from '@/lib/securityUtils';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Search, Filter, X, ExternalLink, Copy, CheckCircle, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

const attackTypes: AttackType[] = ['SQLi', 'XSS', 'Brute Force', 'DDoS', 'Path Traversal', 'RCE', 'CSRF', 'Auth', 'XXE', 'SSRF', 'NoSQLi','Open Redirect', 'Prototype Pollution', 'HTTP Smuggling', 'Recon', 'Other'];
const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const AttackLogs = () => {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [searchIP, setSearchIP] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterAttackType, setFilterAttackType] = useState<string>('all');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [copied, setCopied] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const result = await getAlerts({
        ip: searchIP || undefined,
        severity: filterSeverity !== 'all' ? filterSeverity : undefined,
        attackType: filterAttackType !== 'all' ? filterAttackType : undefined,
        action: filterAction !== 'all' ? filterAction : undefined,
        limit: 500,
      });
      setAlerts(result.data);
      setTotal(result.total);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAlerts(); }, [searchIP, filterSeverity, filterAttackType, filterAction]);

  const handleCopyIP = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clearFilters = () => {
    setSearchIP('');
    setFilterSeverity('all');
    setFilterAttackType('all');
    setFilterAction('all');
  };

  const hasFilters = searchIP || filterSeverity !== 'all' || filterAttackType !== 'all' || filterAction !== 'all';

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Attack Logs</h1>
            <p className="text-muted-foreground text-sm mt-1">Detailed event viewer for security incidents</p>
          </div>
          <Button variant="ghost" size="sm" onClick={fetchAlerts} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        </div>

        <div className="soc-panel">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Filter className="h-4 w-4" />
              <span>Filters</span>
            </div>
            <div className="relative flex-1 min-w-[200px] max-w-[300px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search by IP..." value={searchIP} onChange={(e) => setSearchIP(e.target.value)} className="pl-10 bg-muted/50" />
            </div>
            <Select value={filterSeverity} onValueChange={setFilterSeverity}>
              <SelectTrigger className="w-[140px] bg-muted/50"><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                {severities.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={filterAttackType} onValueChange={setFilterAttackType}>
              <SelectTrigger className="w-[160px] bg-muted/50"><SelectValue placeholder="Attack Type" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {attackTypes.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={filterAction} onValueChange={setFilterAction}>
              <SelectTrigger className="w-[130px] bg-muted/50"><SelectValue placeholder="Action" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Actions</SelectItem>
                <SelectItem value="blocked">Blocked</SelectItem>
                <SelectItem value="allowed">Allowed</SelectItem>
              </SelectContent>
            </Select>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters} className="text-muted-foreground">
                <X className="h-4 w-4 mr-1" />Clear
              </Button>
            )}
            <div className="ml-auto text-sm text-muted-foreground">
              <span className="font-mono">{total}</span> events
            </div>
          </div>
        </div>

        <div className="soc-panel overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center h-40">
              <div className="animate-spin h-6 w-6 border-2 border-primary border-t-transparent rounded-full" />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Country</th>
                    <th>Target URL</th>
                    <th>Attack Type</th>
                    <th>Severity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr key={alert.id} onClick={() => setSelectedAlert(alert)} className={cn(alert.severity === 'critical' && 'border-l-2 border-l-severity-critical')}>
                      <td className="text-muted-foreground whitespace-nowrap">{formatTimestamp(new Date(alert.timestamp))}</td>
                      <td><span className="font-mono text-primary">{alert.sourceIP}</span></td>
                      <td>
                        <span className="flex items-center gap-1">
                          {getCountryFlag(alert.countryCode)}
                          <span className="text-muted-foreground">{alert.countryCode}</span>
                        </span>
                      </td>
                      <td className="max-w-[200px] truncate text-muted-foreground">{alert.targetURL}</td>
                      <td className="font-medium">{alert.attackType}</td>
                      <td><SeverityBadge severity={alert.severity as any} /></td>
                      <td><ActionBadge action={alert.action as any} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <Sheet open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
          <SheetContent className="w-[500px] sm:max-w-[500px] bg-card border-border overflow-y-auto">
            {selectedAlert && (
              <>
                <SheetHeader>
                  <SheetTitle className="flex items-center gap-3">
                    <span>{selectedAlert.attackType} Attack</span>
                    <SeverityBadge severity={selectedAlert.severity as any} />
                  </SheetTitle>
                  <SheetDescription>{formatTimestamp(new Date(selectedAlert.timestamp))}</SheetDescription>
                </SheetHeader>
                <div className="mt-6 space-y-6">
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground uppercase tracking-wide">Source IP</label>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-lg text-primary">{selectedAlert.sourceIP}</span>
                      <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => handleCopyIP(selectedAlert.sourceIP)}>
                        {copied ? <CheckCircle className="h-4 w-4 text-severity-safe" /> : <Copy className="h-4 w-4" />}
                      </Button>
                      <Button variant="ghost" size="icon" className="h-8 w-8" asChild>
                        <a href={`/ip-intel?ip=${selectedAlert.sourceIP}`}><ExternalLink className="h-4 w-4" /></a>
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground uppercase tracking-wide">Location</label>
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{getCountryFlag(selectedAlert.countryCode)}</span>
                      <span>{selectedAlert.country}</span>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground uppercase tracking-wide">Target URL</label>
                    <div className="font-mono text-sm bg-muted/50 p-3 rounded-lg break-all">
                      <span className="text-severity-medium">{selectedAlert.requestMethod}</span>{' '}{selectedAlert.targetURL}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground uppercase tracking-wide">Action Taken</label>
                    <ActionBadge action={selectedAlert.action as any} />
                  </div>
                  {selectedAlert.ruleId && (
                    <div className="space-y-2">
                      <label className="text-xs text-muted-foreground uppercase tracking-wide">Matched Rule</label>
                      <div className="bg-muted/50 p-3 rounded-lg">
                        <div className="font-mono text-sm">{selectedAlert.ruleId}</div>
                        <div className="text-sm text-muted-foreground mt-1">{selectedAlert.ruleName}</div>
                      </div>
                    </div>
                  )}
                  {selectedAlert.payload && (
                    <div className="space-y-2">
                      <label className="text-xs text-muted-foreground uppercase tracking-wide">Malicious Payload</label>
                      <div className="font-mono text-sm bg-severity-critical/10 border border-severity-critical/20 p-3 rounded-lg break-all text-severity-critical">
                        {selectedAlert.payload}
                      </div>
                    </div>
                  )}
                  {selectedAlert.userAgent && (
                    <div className="space-y-2">
                      <label className="text-xs text-muted-foreground uppercase tracking-wide">User Agent</label>
                      <div className="text-sm text-muted-foreground bg-muted/50 p-3 rounded-lg break-all">{selectedAlert.userAgent}</div>
                    </div>
                  )}
                </div>
              </>
            )}
          </SheetContent>
        </Sheet>
      </div>
    </DashboardLayout>
  );
};

export default AttackLogs;
