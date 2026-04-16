import { useState, useEffect } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { getIncidents, updateIncident, type IncidentItem } from '@/lib/api';
import { SeverityBadge } from '@/components/dashboard/SeverityBadge';
import { formatTimestamp, getCountryFlag } from '@/lib/securityUtils';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertTriangle, Clock, Users, Target, MessageSquare, CheckCircle, Search as SearchIcon, XCircle, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

const statusColors: Record<string, string> = {
  open: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30',
  investigating: 'bg-severity-medium/20 text-severity-medium border-severity-medium/30',
  resolved: 'bg-severity-safe/20 text-severity-safe border-severity-safe/30',
  closed: 'bg-muted text-muted-foreground border-muted',
};

const statusIcons: Record<string, React.ReactNode> = {
  open: <AlertTriangle className="h-3 w-3" />,
  investigating: <SearchIcon className="h-3 w-3" />,
  resolved: <CheckCircle className="h-3 w-3" />,
  closed: <XCircle className="h-3 w-3" />,
};

const Incidents = () => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const result = await getIncidents();
      setIncidents(result.data);
      setSummary(result.summary);
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchIncidents(); }, []);

  const handleStatusChange = async (id: string, status: string) => {
    try {
      const updated = await updateIncident(id, { status: status as any });
      setIncidents(prev => prev.map(i => i.id === id ? updated : i));
      if (selectedIncident?.id === id) setSelectedIncident(updated);
    } catch (err) {
      console.error('Failed to update incident:', err);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Incidents</h1>
            <p className="text-muted-foreground text-sm mt-1">Grouped security events and incident response</p>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-severity-critical animate-pulse" />
              <span className="text-muted-foreground">{summary.open ?? 0} Open</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-severity-medium" />
              <span className="text-muted-foreground">{summary.investigating ?? 0} Investigating</span>
            </div>
            <Button variant="ghost" size="sm" onClick={fetchIncidents} disabled={loading}>
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin h-6 w-6 border-2 border-primary border-t-transparent rounded-full" />
          </div>
        ) : incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-60 text-center soc-panel">
            <AlertTriangle className="h-12 w-12 text-muted-foreground mb-4 opacity-40" />
            <h3 className="text-lg font-semibold mb-1">No Incidents Yet</h3>
            <p className="text-sm text-muted-foreground max-w-sm">
              Incidents are automatically created when 5 or more related attacks are detected within an hour.
              Trigger some WAF alerts to see incidents appear here.
            </p>
            <p className="text-xs text-muted-foreground mt-3 font-mono bg-muted/50 px-3 py-2 rounded">
              curl "http://localhost:5000/test?id=1'+OR+'1'='1"
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {incidents.map((incident) => (
              <div
                key={incident.id}
                onClick={() => setSelectedIncident(incident)}
                className={cn(
                  "soc-panel cursor-pointer transition-all hover:border-primary/30",
                  incident.status === 'open' && "border-l-4 border-l-severity-critical",
                  incident.status === 'investigating' && "border-l-4 border-l-severity-medium"
                )}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="font-mono text-sm text-muted-foreground">{incident.id}</span>
                      <SeverityBadge severity={incident.severity as any} />
                      <Badge variant="outline" className={cn("capitalize flex items-center gap-1", statusColors[incident.status])}>
                        {statusIcons[incident.status]}{incident.status}
                      </Badge>
                    </div>
                    <h3 className="text-lg font-semibold mb-2">{incident.title}</h3>
                    <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Clock className="h-4 w-4" />
                        <span>{formatTimestamp(new Date(incident.timeRange.start))} — {formatTimestamp(new Date(incident.timeRange.end))}</span>
                      </div>
                      <div className="flex items-center gap-1"><Target className="h-4 w-4" /><span>{incident.eventCount} events</span></div>
                      <div className="flex items-center gap-1"><Users className="h-4 w-4" /><span>{incident.relatedIPs.length} IPs</span></div>
                    </div>
                  </div>
                  {incident.assignee && (
                    <div className="text-right text-sm">
                      <div className="text-muted-foreground">Assigned to</div>
                      <div className="font-medium">{incident.assignee}</div>
                    </div>
                  )}
                </div>
                <div className="mt-4 pt-4 border-t border-border flex flex-wrap gap-2">
                  {incident.affectedEndpoints.map((endpoint) => (
                    <Badge key={endpoint} variant="secondary" className="font-mono text-xs">{endpoint}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        <Sheet open={!!selectedIncident} onOpenChange={() => setSelectedIncident(null)}>
          <SheetContent className="w-[600px] sm:max-w-[600px] bg-card border-border overflow-y-auto">
            {selectedIncident && (
              <>
                <SheetHeader>
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={selectedIncident.severity as any} />
                    <Badge variant="outline" className={cn("capitalize flex items-center gap-1", statusColors[selectedIncident.status])}>
                      {statusIcons[selectedIncident.status]}{selectedIncident.status}
                    </Badge>
                  </div>
                  <SheetTitle className="text-xl mt-2">{selectedIncident.title}</SheetTitle>
                  <SheetDescription className="font-mono">{selectedIncident.id}</SheetDescription>
                </SheetHeader>

                <div className="mt-6 space-y-6">
                  {/* Status Update */}
                  <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-lg">
                    <span className="text-sm font-medium">Update Status:</span>
                    <Select value={selectedIncident.status} onValueChange={(v) => handleStatusChange(selectedIncident.id, v)}>
                      <SelectTrigger className="w-[160px]"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {['open', 'investigating', 'resolved', 'closed'].map(s => (
                          <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="soc-panel">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Start Time</div>
                      <div className="font-mono text-sm">{formatTimestamp(new Date(selectedIncident.timeRange.start))}</div>
                    </div>
                    <div className="soc-panel">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">End Time</div>
                      <div className="font-mono text-sm">{formatTimestamp(new Date(selectedIncident.timeRange.end))}</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center p-4 bg-muted/30 rounded-lg">
                      <div className="text-2xl font-bold">{selectedIncident.eventCount}</div>
                      <div className="text-xs text-muted-foreground">Total Events</div>
                    </div>
                    <div className="text-center p-4 bg-muted/30 rounded-lg">
                      <div className="text-2xl font-bold">{selectedIncident.relatedIPs.length}</div>
                      <div className="text-xs text-muted-foreground">Related IPs</div>
                    </div>
                    <div className="text-center p-4 bg-muted/30 rounded-lg">
                      <div className="text-2xl font-bold">{selectedIncident.affectedEndpoints.length}</div>
                      <div className="text-xs text-muted-foreground">Endpoints</div>
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Related IP Addresses</div>
                    <div className="space-y-2">
                      {selectedIncident.relatedIPs.map((ip) => (
                        <div key={ip} className="font-mono text-sm bg-muted/50 p-2 rounded flex items-center justify-between">
                          <span>{ip}</span>
                          <a href={`/ip-intel?ip=${ip}`} className="text-primary hover:underline text-xs">Investigate →</a>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Affected Endpoints</div>
                    <div className="flex flex-wrap gap-2">
                      {selectedIncident.affectedEndpoints.map((endpoint) => (
                        <Badge key={endpoint} variant="secondary" className="font-mono">{endpoint}</Badge>
                      ))}
                    </div>
                  </div>

                  {selectedIncident.notes && (
                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2 flex items-center gap-2">
                        <MessageSquare className="h-3 w-3" />Notes
                      </div>
                      <div className="bg-muted/50 p-4 rounded-lg text-sm">{selectedIncident.notes}</div>
                    </div>
                  )}

                  {selectedIncident.events && selectedIncident.events.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-3">Event Timeline</div>
                      <div className="space-y-3">
                        {selectedIncident.events.slice(0, 5).map((event, index) => (
                          <div key={event.id} className="flex gap-3">
                            <div className="flex flex-col items-center">
                              <div className={cn("w-2 h-2 rounded-full",
                                event.severity === 'critical' ? 'bg-severity-critical' :
                                event.severity === 'high' ? 'bg-severity-high' : 'bg-severity-medium'
                              )} />
                              {index < 4 && <div className="w-px h-full bg-border" />}
                            </div>
                            <div className="flex-1 pb-3">
                              <div className="flex items-center gap-2 text-sm">
                                <span className="font-medium">{event.attackType}</span>
                                <SeverityBadge severity={event.severity as any} />
                              </div>
                              <div className="text-xs text-muted-foreground mt-1">
                                {formatTimestamp(new Date(event.timestamp))} • {event.sourceIP}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
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

export default Incidents;
