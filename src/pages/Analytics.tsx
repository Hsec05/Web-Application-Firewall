import { useEffect, useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { getAnalytics, type AnalyticsResponse } from '@/lib/api';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell } from 'recharts';
import { TrendingUp, Target, Clock, ShieldX } from 'lucide-react';

const Analytics = () => {
  const [data, setData] = useState<AnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAnalytics()
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const severityColors: Record<string, string> = {
    critical: 'hsl(0, 84%, 60%)', high: 'hsl(25, 95%, 53%)', medium: 'hsl(45, 93%, 47%)',
    low: 'hsl(217, 91%, 60%)', info: 'hsl(187, 85%, 53%)',
  };

  const tooltipStyle = {
    contentStyle: { backgroundColor: 'hsl(222, 47%, 9%)', border: '1px solid hsl(217, 33%, 18%)', borderRadius: '8px', color: 'hsl(210, 40%, 96%)' },
    labelStyle: { color: 'hsl(210, 40%, 96%)' },
    itemStyle: { color: 'hsl(210, 40%, 96%)' },
  };

  if (loading) {
    return <DashboardLayout><div className="flex items-center justify-center h-64"><div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" /></div></DashboardLayout>;
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold">Security Analytics</h1>
          <p className="text-muted-foreground text-sm mt-1">Trends, patterns, and security insights — {data?.totalAnalyzed ?? 0} events analyzed</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="soc-panel">
            <div className="soc-panel-header">
              <h3 className="soc-panel-title"><Target className="h-4 w-4 text-primary" />Most Targeted URLs</h3>
            </div>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data?.topURLs} layout="vertical" margin={{ left: 80, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217, 33%, 18%)" horizontal={false} />
                  <XAxis type="number" stroke="hsl(215, 20%, 55%)" fontSize={10} />
                  <YAxis type="category" dataKey="url" stroke="hsl(215, 20%, 55%)" fontSize={10} width={80} tickFormatter={(v) => v.length > 15 ? v.slice(0, 15) + '...' : v} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="count" fill="hsl(187, 85%, 53%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header">
              <h3 className="soc-panel-title"><ShieldX className="h-4 w-4 text-severity-high" />Attack Types</h3>
            </div>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data?.attackTypeBreakdown.slice(0, 6)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217, 33%, 18%)" vertical={false} />
                  <XAxis dataKey="type" stroke="hsl(215, 20%, 55%)" fontSize={10} angle={-45} textAnchor="end" height={60} />
                  <YAxis stroke="hsl(215, 20%, 55%)" fontSize={10} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {data?.attackTypeBreakdown.slice(0, 6).map((_, i) => (
                      <Cell key={i} fill={['hsl(0,84%,60%)', 'hsl(25,95%,53%)', 'hsl(45,93%,47%)', 'hsl(187,85%,53%)', 'hsl(280,65%,60%)', 'hsl(142,76%,46%)'][i]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header">
              <h3 className="soc-panel-title"><Clock className="h-4 w-4 text-primary" />Peak Attack Times (24h)</h3>
            </div>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data?.hourlyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217, 33%, 18%)" />
                  <XAxis dataKey="hour" stroke="hsl(215, 20%, 55%)" fontSize={10} interval={2} />
                  <YAxis stroke="hsl(215, 20%, 55%)" fontSize={10} />
                  <Tooltip {...tooltipStyle} />
                  <Line type="monotone" dataKey="attacks" stroke="hsl(0, 84%, 60%)" strokeWidth={2} dot={{ fill: 'hsl(0, 84%, 60%)', strokeWidth: 0 }} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header">
              <h3 className="soc-panel-title"><TrendingUp className="h-4 w-4 text-severity-medium" />Severity Distribution</h3>
            </div>
            <div className="h-[300px] flex items-center">
              <ResponsiveContainer width="60%" height="100%">
                <PieChart>
                  <Pie data={data?.severityDistribution} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="count" nameKey="severity" paddingAngle={2}>
                    {data?.severityDistribution.map((entry) => (
                      <Cell key={entry.severity} fill={severityColors[entry.severity]} stroke="hsl(222, 47%, 6%)" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 space-y-2">
                {data?.severityDistribution.map((item) => (
                  <div key={item.severity} className="flex items-center gap-2 text-sm">
                    <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: severityColors[item.severity] }} />
                    <span className="capitalize text-muted-foreground">{item.severity}</span>
                    <span className="font-mono ml-auto">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="soc-panel">
          <div className="soc-panel-header"><h3 className="soc-panel-title">Top Attacking IPs</h3></div>
          <div className="overflow-x-auto">
            <table className="soc-table">
              <thead>
                <tr><th>Rank</th><th>IP Address</th><th>Country</th><th>Attack Count</th><th>Top Attack Type</th><th>Risk Score</th></tr>
              </thead>
              <tbody>
                {data?.topAttackingIPs.map((item, index) => (
                  <tr key={item.ip}>
                    <td className="font-bold text-muted-foreground">#{index + 1}</td>
                    <td className="font-mono text-primary">{item.ip}</td>
                    <td>{item.country}</td>
                    <td className="font-mono font-bold">{item.count}</td>
                    <td>{item.attackTypes[0] || 'Mixed'}</td>
                    <td><span className={`font-bold ${item.riskScore >= 70 ? 'text-severity-critical' : item.riskScore >= 40 ? 'text-severity-high' : 'text-severity-medium'}`}>{item.riskScore}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Analytics;
