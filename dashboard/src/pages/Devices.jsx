import React, { useState, useEffect, useCallback } from 'react';
import {
  Monitor,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Cpu,
  HardDrive,
  Clock,
  ExternalLink,
  Shield,
  Activity,
} from 'lucide-react';
import { getDevices, getDeviceStats, getDeviceHistory } from '../api/client';
import StatusDot from '../components/StatusDot';
import DataTable from '../components/DataTable';
import FilterBar from '../components/FilterBar';
import DetailDrawer from '../components/DetailDrawer';

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Drawer state
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [deviceHistory, setDeviceHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [devList, statRes] = await Promise.all([getDevices(), getDeviceStats()]);
      setDevices(Array.isArray(devList) ? devList : devList.devices || []);
      setStats(statRes);
    } catch (err) {
      console.error('Error fetching devices:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRowClick = async (device) => {
    setSelectedDevice(device);
    setHistoryLoading(true);
    try {
      const history = await getDeviceHistory(device.agent_id);
      setDeviceHistory(Array.isArray(history) ? history : history.snapshots || []);
    } catch (err) {
      console.error('Failed to load device history:', err);
      setDeviceHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Filtered devices
  const filteredDevices = devices.filter((d) => {
    const matchesSearch =
      !search ||
      d.agent_id?.toLowerCase().includes(search.toLowerCase()) ||
      d.hostname?.toLowerCase().includes(search.toLowerCase()) ||
      d.ip_address?.toLowerCase().includes(search.toLowerCase());

    const matchesOs = !osFilter || d.os?.toLowerCase().includes(osFilter.toLowerCase());
    const matchesStatus =
      !statusFilter ||
      (statusFilter === 'online' ? d.status === 'online' : d.status !== 'online');

    return matchesSearch && matchesOs && matchesStatus;
  });

  const columns = [
    {
      key: 'status',
      label: 'Status',
      width: '100px',
      render: (val, row) => <StatusDot status={row.status || 'offline'} showLabel={true} />,
    },
    {
      key: 'hostname',
      label: 'Hostname / ID',
      sortable: true,
      render: (val, row) => (
        <div>
          <div className="font-medium text-heading">{row.hostname || 'Unknown'}</div>
          <div className="text-xs text-muted mono-badge">{row.agent_id}</div>
        </div>
      ),
    },
    {
      key: 'ip_address',
      label: 'IP Address',
      sortable: true,
      render: (val) => <code className="mono-badge">{val || '—'}</code>,
    },
    {
      key: 'os',
      label: 'OS / Version',
      render: (val, row) => (
        <span>
          {val || 'Unknown'} {row.os_version ? `(${row.os_version})` : ''}
        </span>
      ),
    },
    {
      key: 'arch',
      label: 'Architecture',
      render: (val) => val || 'x86_64',
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      sortable: true,
      render: (val) =>
        val ? new Date(val).toLocaleString() : 'Never',
    },
  ];

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Device & Asset Inventory</h1>
          <p className="page-subtitle">Managed endpoint agents and operational status</p>
        </div>
        <button type="button" className="btn-secondary" onClick={fetchData}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Summary Stats Cards */}
      <div className="stats-row">
        <div className="stat-pill">
          <Monitor size={18} className="text-accent-blue" />
          <span className="stat-pill-label">Total Devices:</span>
          <span className="stat-pill-val">{stats?.total_devices ?? devices.length}</span>
        </div>
        <div className="stat-pill">
          <CheckCircle2 size={18} className="text-accent-green" />
          <span className="stat-pill-label">Online:</span>
          <span className="stat-pill-val text-accent-green">
            {stats?.online_devices ?? devices.filter((d) => d.status === 'online').length}
          </span>
        </div>
        <div className="stat-pill">
          <XCircle size={18} className="text-accent-red" />
          <span className="stat-pill-label">Offline:</span>
          <span className="stat-pill-val text-accent-red">
            {stats?.offline_devices ?? devices.filter((d) => d.status !== 'online').length}
          </span>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Filter by hostname, IP, agent ID..."
        filters={[
          {
            id: 'status',
            label: 'All Statuses',
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { value: 'online', label: 'Online Only' },
              { value: 'offline', label: 'Offline Only' },
            ],
          },
          {
            id: 'os',
            label: 'All Operating Systems',
            value: osFilter,
            onChange: setOsFilter,
            options: [
              { value: 'windows', label: 'Windows' },
              { value: 'linux', label: 'Linux' },
              { value: 'darwin', label: 'macOS' },
            ],
          },
        ]}
        onReset={() => {
          setSearch('');
          setOsFilter('');
          setStatusFilter('');
        }}
      />

      {/* Table */}
      <DataTable
        columns={columns}
        data={filteredDevices}
        loading={loading}
        emptyMessage="No devices match the selected filters."
        onRowClick={handleRowClick}
      />

      {/* Device Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        title={selectedDevice?.hostname || 'Device Details'}
        subtitle={`Agent ID: ${selectedDevice?.agent_id || ''}`}
        width="600px"
      >
        {selectedDevice && (
          <div className="drawer-content-stack">
            {/* Device Info Summary */}
            <div className="info-grid">
              <div className="info-box">
                <span className="info-label">Status</span>
                <StatusDot status={selectedDevice.status} showLabel={true} />
              </div>
              <div className="info-box">
                <span className="info-label">IP Address</span>
                <span className="info-value font-mono">{selectedDevice.ip_address || '—'}</span>
              </div>
              <div className="info-box">
                <span className="info-label">Operating System</span>
                <span className="info-value">
                  {selectedDevice.os} {selectedDevice.os_version}
                </span>
              </div>
              <div className="info-box">
                <span className="info-label">Architecture</span>
                <span className="info-value font-mono">{selectedDevice.arch || 'x86_64'}</span>
              </div>
              <div className="info-box">
                <span className="info-label">First Enrolled</span>
                <span className="info-value">
                  {selectedDevice.first_seen
                    ? new Date(selectedDevice.first_seen).toLocaleString()
                    : '—'}
                </span>
              </div>
              <div className="info-box">
                <span className="info-label">Last Check-in</span>
                <span className="info-value">
                  {selectedDevice.last_seen
                    ? new Date(selectedDevice.last_seen).toLocaleString()
                    : '—'}
                </span>
              </div>
            </div>

            {/* Telemetry Snapshot History */}
            <div className="drawer-section">
              <h4 className="section-title">Telemetry Snapshot History</h4>
              {historyLoading ? (
                <div className="loading-box">
                  <RefreshCw size={18} className="animate-spin text-accent-blue" />
                  <span>Loading snapshots...</span>
                </div>
              ) : deviceHistory.length === 0 ? (
                <p className="text-muted text-sm italic">No historic snapshots on record.</p>
              ) : (
                <div className="history-timeline">
                  {deviceHistory.slice(0, 10).map((snap, i) => (
                    <div key={i} className="history-item">
                      <div className="history-dot" />
                      <div className="history-body">
                        <span className="history-time">
                          {new Date(snap.timestamp || snap.created_at).toLocaleString()}
                        </span>
                        <div className="history-metrics">
                          {snap.cpu_usage !== undefined && (
                            <span className="metric-tag">CPU: {snap.cpu_usage}%</span>
                          )}
                          {snap.memory_usage !== undefined && (
                            <span className="metric-tag">RAM: {snap.memory_usage}%</span>
                          )}
                          {snap.ip_address && (
                            <span className="metric-tag">IP: {snap.ip_address}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
