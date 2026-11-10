import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert,
  Server,
  Lock,
  Flame,
  RefreshCw,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { getAlertStats, getDeviceStats, getEventStats, getAlerts } from '../api/client';
import KpiCard from '../components/KpiCard';
import SeverityBadge from '../components/SeverityBadge';
import { ThreatTimelineChart, TopRulesChart, SeverityDonutChart } from '../components/Charts';

export default function Overview() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [alertStats, setAlertStats] = useState(null);
  const [deviceStats, setDeviceStats] = useState(null);
  const [eventStats, setEventStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const fetchData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const [alertsRes, devicesRes, eventsRes, recentRes] = await Promise.allSettled([
        getAlertStats(),
        getDeviceStats(),
        getEventStats(),
        getAlerts({ limit: 10 }),
      ]);

      if (alertsRes.status === 'fulfilled') setAlertStats(alertsRes.value);
      if (devicesRes.status === 'fulfilled') setDeviceStats(devicesRes.value);
      if (eventsRes.status === 'fulfilled') setEventStats(eventsRes.value);
      if (recentRes.status === 'fulfilled') {
        const data = recentRes.value;
        setRecentAlerts(Array.isArray(data) ? data : data.alerts || data.items || []);
      }
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed to load overview telemetry:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Auto-refresh every 15s
    const timer = setInterval(() => fetchData(false), 15000);
    return () => clearInterval(timer);
  }, [fetchData]);

  // Compute critical alert count
  const criticalCount =
    alertStats?.severity_breakdown?.find((s) => s.severity === 'CRITICAL')?.count || 0;

  return (
    <div className="page-container">
      {/* Header bar */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Command Center</h1>
          <p className="page-subtitle">Real-time threat detection & system telemetry</p>
        </div>
        <div className="page-header-actions">
          <span className="live-indicator">
            <span className="live-pulse" /> Live Telemetry
          </span>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => fetchData(true)}
            disabled={refreshing}
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="kpi-grid">
        <KpiCard
          label="Active Agents"
          value={deviceStats?.online_devices ?? '—'}
          sub={`Total devices: ${deviceStats?.total_devices ?? 0}`}
          icon={Server}
          accent="cyan"
          glow={true}
        />
        <KpiCard
          label="Threats (24h)"
          value={alertStats?.alerts_today ?? alertStats?.total_alerts ?? '0'}
          sub={`${alertStats?.unresolved_alerts ?? 0} unresolved`}
          icon={ShieldAlert}
          accent="amber"
        />
        <KpiCard
          label="Critical Alerts"
          value={criticalCount}
          sub="Requires immediate response"
          icon={Flame}
          accent="red"
          glow={criticalCount > 0}
        />
        <KpiCard
          label="Auth Failures (24h)"
          value={eventStats?.failed_logons_24h ?? '0'}
          sub={`Total events: ${eventStats?.total_events ?? 0}`}
          icon={Lock}
          accent="blue"
        />
      </div>

      {/* Visualizations Section */}
      <div className="dashboard-grid-2col">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Threat Timeline (Last 24 Hours)</h2>
            <span className="card-badge">Hourly Aggregation</span>
          </div>
          <div className="card-content">
            <ThreatTimelineChart data={alertStats?.timeline_24h || []} />
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Top Detection Rules</h2>
            <span className="card-badge">By Trigger Count</span>
          </div>
          <div className="card-content">
            <TopRulesChart data={alertStats?.top_rules || []} />
          </div>
        </div>
      </div>

      {/* Secondary Row: Severity Distribution & Live Threat Stream */}
      <div className="dashboard-grid-3col">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Threat Severity Distribution</h2>
          </div>
          <div className="card-content">
            <SeverityDonutChart data={alertStats?.severity_breakdown || []} />
          </div>
        </div>

        <div className="card grid-span-2">
          <div className="card-header">
            <div className="flex-between w-full">
              <h2 className="card-title">Recent Threat Feed</h2>
              <Link to="/threats" className="card-action-link">
                View All <ArrowRight size={14} />
              </Link>
            </div>
          </div>
          <div className="card-content p-0">
            {recentAlerts.length === 0 ? (
              <div className="table-empty py-8">
                <p className="text-muted text-sm">No threats logged yet</p>
              </div>
            ) : (
              <div className="feed-list">
                {recentAlerts.slice(0, 6).map((alert) => (
                  <div key={alert.id} className="feed-item">
                    <div className="feed-item-left">
                      <SeverityBadge severity={alert.severity} />
                      <div className="feed-item-details">
                        <span className="feed-item-title">{alert.rule_name}</span>
                        <span className="feed-item-meta">
                          Agent: <code className="mono-badge">{alert.agent_id}</code> •{' '}
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                    <div>
                      {alert.resolved ? (
                        <span className="badge-resolved">Resolved</span>
                      ) : (
                        <span className="badge-open">Open</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
