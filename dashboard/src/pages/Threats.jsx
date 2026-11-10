import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  RefreshCw,
  Eye,
  Check,
  Undo2,
  Clock,
  Terminal,
} from 'lucide-react';
import { getAlerts, getAlertById, resolveAlert } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import DataTable from '../components/DataTable';
import FilterBar from '../components/FilterBar';
import DetailDrawer from '../components/DetailDrawer';

export default function Threats() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [resolvedFilter, setResolvedFilter] = useState('');

  // Detail drawer
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [resolvingId, setResolvingId] = useState(null);

  const fetchAlertsData = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        limit: pageSize,
        offset: (page - 1) * pageSize,
      };
      if (severityFilter) params.severity = severityFilter;
      if (resolvedFilter !== '') params.resolved = resolvedFilter === 'true';
      if (search) params.rule_name = search;

      const res = await getAlerts(params);
      const items = Array.isArray(res) ? res : res.alerts || res.items || [];
      setAlerts(items);
      setTotalAlerts(res.total ?? items.length);
    } catch (err) {
      console.error('Failed to load alerts:', err);
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, [page, severityFilter, resolvedFilter, search]);

  useEffect(() => {
    fetchAlertsData();
  }, [fetchAlertsData]);

  const handleToggleResolve = async (alertItem, e) => {
    if (e) e.stopPropagation();
    setResolvingId(alertItem.id);
    try {
      const newStatus = !alertItem.resolved;
      await resolveAlert(alertItem.id, newStatus);
      // Update local state
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertItem.id ? { ...a, resolved: newStatus } : a))
      );
      if (selectedAlert?.id === alertItem.id) {
        setSelectedAlert((prev) => ({ ...prev, resolved: newStatus }));
      }
    } catch (err) {
      console.error('Failed to toggle alert status:', err);
    } finally {
      setResolvingId(null);
    }
  };

  const handleOpenDetail = async (alertItem) => {
    setSelectedAlert(alertItem);
    setDrawerLoading(true);
    try {
      const full = await getAlertById(alertItem.id);
      setSelectedAlert(full || alertItem);
    } catch (err) {
      console.error('Failed to get full alert details:', err);
    } finally {
      setDrawerLoading(false);
    }
  };

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      width: '120px',
      sortable: true,
      render: (val) => <SeverityBadge severity={val} />,
    },
    {
      key: 'rule_name',
      label: 'Threat / Rule Name',
      sortable: true,
      render: (val, row) => (
        <div>
          <div className="font-semibold text-heading">{val}</div>
          <div className="text-xs text-muted">ID: {row.id?.slice(0, 8)}...</div>
        </div>
      ),
    },
    {
      key: 'agent_id',
      label: 'Agent ID',
      render: (val) => <code className="mono-badge">{val || '—'}</code>,
    },
    {
      key: 'timestamp',
      label: 'Detected At',
      sortable: true,
      render: (val) => (val ? new Date(val).toLocaleString() : '—'),
    },
    {
      key: 'resolved',
      label: 'Status',
      width: '120px',
      render: (val, row) => (
        <button
          type="button"
          className={`btn-status ${val ? 'resolved' : 'open'}`}
          onClick={(e) => handleToggleResolve(row, e)}
          disabled={resolvingId === row.id}
        >
          {resolvingId === row.id ? (
            <RefreshCw size={12} className="animate-spin" />
          ) : val ? (
            <>
              <Check size={12} /> Resolved
            </>
          ) : (
            <>
              <AlertTriangle size={12} /> Open
            </>
          )}
        </button>
      ),
    },
    {
      key: 'actions',
      label: '',
      width: '80px',
      render: (_, row) => (
        <button
          type="button"
          className="btn-icon"
          title="View Details"
          onClick={() => handleOpenDetail(row)}
        >
          <Eye size={15} />
        </button>
      ),
    },
  ];

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Management</h1>
          <p className="page-subtitle">Security detections, incident response, and triage</p>
        </div>
        <button type="button" className="btn-secondary" onClick={fetchAlertsData}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Filter by rule name or ID..."
        filters={[
          {
            id: 'severity',
            label: 'All Severities',
            value: severityFilter,
            onChange: setSeverityFilter,
            options: [
              { value: 'CRITICAL', label: 'CRITICAL' },
              { value: 'HIGH', label: 'HIGH' },
              { value: 'MEDIUM', label: 'MEDIUM' },
              { value: 'LOW', label: 'LOW' },
            ],
          },
          {
            id: 'status',
            label: 'All Statuses',
            value: resolvedFilter,
            onChange: setResolvedFilter,
            options: [
              { value: 'false', label: 'Open Only' },
              { value: 'true', label: 'Resolved Only' },
            ],
          },
        ]}
        onReset={() => {
          setSearch('');
          setSeverityFilter('');
          setResolvedFilter('');
          setPage(1);
        }}
      />

      {/* Alerts Table */}
      <DataTable
        columns={columns}
        data={alerts}
        loading={loading}
        emptyMessage="No security alerts match the query criteria."
        onRowClick={handleOpenDetail}
        pagination={{
          page,
          pageSize,
          total: totalAlerts,
          onPageChange: setPage,
        }}
      />

      {/* Alert Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert?.rule_name || 'Threat Incident Details'}
        subtitle={`Alert UUID: ${selectedAlert?.id || ''}`}
        width="680px"
      >
        {selectedAlert && (
          <div className="drawer-content-stack">
            {/* Header badges */}
            <div className="flex-between">
              <SeverityBadge severity={selectedAlert.severity} />
              <button
                type="button"
                className={`btn-status large ${selectedAlert.resolved ? 'resolved' : 'open'}`}
                onClick={(e) => handleToggleResolve(selectedAlert, e)}
                disabled={resolvingId === selectedAlert.id}
              >
                {selectedAlert.resolved ? (
                  <>
                    <Undo2 size={14} /> Reopen Alert
                  </>
                ) : (
                  <>
                    <Check size={14} /> Mark as Resolved
                  </>
                )}
              </button>
            </div>

            {/* Metadata Summary */}
            <div className="info-grid mt-4">
              <div className="info-box">
                <span className="info-label">Host / Agent</span>
                <span className="info-value font-mono">{selectedAlert.agent_id}</span>
              </div>
              <div className="info-box">
                <span className="info-label">Timestamp</span>
                <span className="info-value">
                  {new Date(selectedAlert.timestamp).toLocaleString()}
                </span>
              </div>
              <div className="info-box">
                <span className="info-label">Status</span>
                <span className="info-value">
                  {selectedAlert.resolved ? 'RESOLVED' : 'ACTIVE / OPEN'}
                </span>
              </div>
              <div className="info-box">
                <span className="info-label">Rule Name</span>
                <span className="info-value">{selectedAlert.rule_name}</span>
              </div>
            </div>

            {/* Context & Raw Event Data */}
            <div className="drawer-section mt-6">
              <div className="flex-between">
                <h4 className="section-title">Context & Event Evidence</h4>
                <Terminal size={14} className="text-muted" />
              </div>
              <pre className="code-block">
                {JSON.stringify(
                  typeof selectedAlert.context === 'string'
                    ? JSON.parse(selectedAlert.context || '{}')
                    : selectedAlert.context || selectedAlert,
                  null,
                  2
                )}
              </pre>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
