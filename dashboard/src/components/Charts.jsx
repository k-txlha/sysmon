import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
  PieChart,
  Pie,
} from 'recharts';

// Custom dark tooltip
function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="chart-tooltip">
        <div className="tooltip-label">{label}</div>
        {payload.map((entry, index) => (
          <div key={`item-${index}`} className="tooltip-item">
            <span
              className="tooltip-dot"
              style={{ backgroundColor: entry.color || entry.stroke || entry.fill }}
            />
            <span className="tooltip-name">{entry.name}:</span>
            <span className="tooltip-val">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
}

/**
 * 24h Threat Activity Area Chart
 * Props:
 *   data: Array<{ hour: string, CRITICAL: number, HIGH: number, MEDIUM: number, LOW: number, total: number }>
 */
export function ThreatTimelineChart({ data = [] }) {
  if (!data || data.length === 0) {
    return (
      <div className="chart-empty-state">
        <span>No threat timeline data available for the last 24 hours.</span>
      </div>
    );
  }

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height={260}>
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#EF4444" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#F97316" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#F97316" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis
            dataKey="hour"
            stroke="#64748B"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
          />
          <YAxis
            stroke="#64748B"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="CRITICAL"
            stackId="1"
            stroke="#EF4444"
            fillOpacity={1}
            fill="url(#colorCritical)"
            name="Critical"
          />
          <Area
            type="monotone"
            dataKey="HIGH"
            stackId="1"
            stroke="#F97316"
            fillOpacity={1}
            fill="url(#colorHigh)"
            name="High"
          />
          <Area
            type="monotone"
            dataKey="MEDIUM"
            stackId="1"
            stroke="#F59E0B"
            fillOpacity={1}
            fill="url(#colorMedium)"
            name="Medium"
          />
          <Area
            type="monotone"
            dataKey="LOW"
            stackId="1"
            stroke="#06B6D4"
            fillOpacity={1}
            fill="url(#colorLow)"
            name="Low"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Top Triggered Rules Bar Chart
 * Props:
 *   data: Array<{ rule_name: string, count: number }>
 */
export function TopRulesChart({ data = [] }) {
  if (!data || data.length === 0) {
    return (
      <div className="chart-empty-state">
        <span>No rule trigger history found.</span>
      </div>
    );
  }

  const colors = ['#3B82F6', '#06B6D4', '#8B5CF6', '#10B981', '#F59E0B'];

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height={260}>
        <BarChart
          layout="vertical"
          data={data}
          margin={{ top: 10, right: 20, left: 40, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
          <XAxis
            type="number"
            stroke="#64748B"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="rule_name"
            stroke="#94A3B8"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
            width={120}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="count" name="Triggers" radius={[0, 4, 4, 0]}>
            {data.map((_, index) => (
              <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Severity Breakdown Donut Chart
 * Props:
 *   data: Array<{ name: string, value: number, color: string }>
 */
export function SeverityDonutChart({ data = [] }) {
  const SEVERITY_COLORS = {
    CRITICAL: '#EF4444',
    HIGH: '#F97316',
    MEDIUM: '#F59E0B',
    LOW: '#06B6D4',
  };

  const chartData = (data || []).map((d) => ({
    name: d.severity || d.name,
    value: d.count || d.value || 0,
    color: SEVERITY_COLORS[d.severity || d.name] || '#3B82F6',
  })).filter(d => d.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="chart-empty-state">
        <span>No severity distribution data.</span>
      </div>
    );
  }

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Tooltip content={<CustomTooltip />} />
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={85}
            paddingAngle={4}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="donut-legend">
        {chartData.map((item) => (
          <div key={item.name} className="legend-item">
            <span className="legend-dot" style={{ backgroundColor: item.color }} />
            <span className="legend-label">{item.name}</span>
            <span className="legend-val">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
