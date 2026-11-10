/**
 * Glassmorphism KPI stat card with accent color stripe and icon.
 *
 * Props:
 *   label   – Metric label (e.g. "Active Agents")
 *   value   – Primary metric value
 *   sub     – Optional secondary text
 *   icon    – Lucide icon component
 *   color   – Accent color key: blue | green | amber | red | purple | cyan
 *   delay   – Animation delay class index (0-4)
 */
export default function KpiCard({ label, value, sub, icon: Icon, color = 'blue', delay = 0 }) {
  return (
    <div className={`kpi-card ${color} animate-in animate-in-delay-${delay}`}>
      <div className="kpi-card-header">
        <span className="kpi-card-label">{label}</span>
        {Icon && (
          <div className={`kpi-card-icon ${color}`}>
            <Icon size={18} />
          </div>
        )}
      </div>
      <div className="kpi-card-value">{value ?? '—'}</div>
      {sub && <div className="kpi-card-sub">{sub}</div>}
    </div>
  );
}
