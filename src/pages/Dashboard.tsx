import { useEffect, useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { MetricCard } from '@/components/dashboard/MetricCard';
import { LiveAlertsPanel } from '@/components/dashboard/LiveAlertsPanel';
import { AttackTypeChart } from '@/components/dashboard/AttackTypeChart';
import { RequestsChart } from '@/components/dashboard/RequestsChart';
import { CountryList } from '@/components/dashboard/CountryList';
import { HighRiskIPs } from '@/components/dashboard/HighRiskIPs';
import { getDashboardMetrics, getLiveAlerts, type DashboardMetricsResponse, type AlertItem } from '@/lib/api';
import { Shield, ShieldX, Users, AlertTriangle } from 'lucide-react';

const Dashboard = () => {
  const [metrics, setMetrics] = useState<DashboardMetricsResponse | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const fetchData = async () => {
    try {
      const [metricsData, alertsData] = await Promise.all([
        getDashboardMetrics(),
        getLiveAlerts(),
      ]);
      setMetrics(metricsData);
      setLiveAlerts(alertsData);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" />
        </div>
      </DashboardLayout>
    );
  }

  const adaptedAlerts = liveAlerts.map(a => ({
    ...a,
    timestamp: new Date(a.timestamp),
    attackType: a.attackType as any,
    severity: a.severity as any,
    action: a.action as any,
  }));

  const adaptedIPProfiles = (metrics?.topAttackingIPs ?? []).map(ip => ({
    ip: ip.ip,
    riskScore: ip.riskScore,
    country: ip.country,
    countryCode: ip.countryCode,
    totalRequests: ip.count,
    blockedRequests: ip.blockedRequests,
    attackTypes: ip.attackTypes,
    isTor: false,
    isVPN: false,
    isProxy: false,
    lastSeen: new Date(),
    firstSeen: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    targetedURLs: [],
  }));

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Security Overview</h1>
            <p className="text-muted-foreground text-sm mt-1">Real-time threat detection and security analytics</p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="w-2 h-2 rounded-full bg-severity-safe animate-pulse" />
            <span className="text-muted-foreground">Updated: {lastUpdated.toLocaleTimeString()}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard title="Total Requests" value={metrics?.totalRequests ?? 0} icon={Shield} iconColor="text-primary" />
          <MetricCard title="Blocked Threats" value={metrics?.blockedRequests ?? 0} icon={ShieldX} iconColor="text-severity-critical" />
          <MetricCard title="Unique Attackers" value={metrics?.uniqueAttackers ?? 0} icon={Users} iconColor="text-severity-high" />
          <MetricCard title="Active Incidents" value={metrics?.activeIncidents ?? 0} icon={AlertTriangle} iconColor="text-severity-medium" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <LiveAlertsPanel alerts={adaptedAlerts} className="h-[400px]" />
          </div>
          <div className="lg:col-span-2">
            <RequestsChart data={metrics?.requestsOverTime ?? []} className="h-[400px]" />
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <AttackTypeChart data={metrics?.topAttackTypes as any ?? []} className="h-[380px]" />
          <CountryList data={metrics?.topCountries ?? []} className="h-[380px]" />
          <HighRiskIPs profiles={adaptedIPProfiles as any} className="h-[380px]" />
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
