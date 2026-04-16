import { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { cn } from '@/lib/utils';
import { AttackType } from '@/types/security';

interface AttackTypeChartProps {
  data: { type: AttackType; count: number }[];
  className?: string;
}

const COLORS = [
  'hsl(187, 85%, 53%)',  // cyan - primary
  'hsl(142, 76%, 46%)',  // green
  'hsl(25, 95%, 53%)',   // orange
  'hsl(0, 84%, 60%)',    // red
  'hsl(280, 65%, 60%)',  // purple
  'hsl(45, 93%, 47%)',   // yellow
  'hsl(200, 80%, 50%)',  // blue
  'hsl(320, 70%, 50%)',  // pink
];

export function AttackTypeChart({ data, className }: AttackTypeChartProps) {
  const chartData = useMemo(() => {
    return data
      .filter(d => d.count > 0)
      .map((item, index) => ({
        name: item.type,
        value: item.count,
        color: COLORS[index % COLORS.length],
      }));
  }, [data]);

  const total = chartData.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className={cn("soc-panel h-full flex flex-col", className)}>
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">Attack Type Distribution</h3>
      </div>

      <div className="flex-1 min-h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={82}
              paddingAngle={2}
              dataKey="value"
            >
              {chartData.map((entry, index) => (
                <Cell 
                  key={`cell-${index}`} 
                  fill={entry.color}
                  stroke="hsl(222, 47%, 6%)"
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'hsl(222, 47%, 9%)',
                border: '1px solid hsl(217, 33%, 18%)',
                borderRadius: '8px',
                color: 'hsl(210, 40%, 96%)',
              }}
              labelStyle={{ color: 'hsl(210, 40%, 96%)' }}
              itemStyle={{ color: 'hsl(210, 40%, 96%)' }}
              formatter={(value: number) => [`${value} (${((value / total) * 100).toFixed(1)}%)`, 'Count']}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Legend — all items, no truncation, full name always visible */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mt-3">
        {chartData.map((item) => (
          <div key={item.name} className="flex items-center gap-2 text-xs min-w-0">
            <div
              className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
              style={{ backgroundColor: item.color }}
            />
            <span className="text-muted-foreground flex-1">{item.name}</span>
            <span className="font-mono text-foreground flex-shrink-0">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
