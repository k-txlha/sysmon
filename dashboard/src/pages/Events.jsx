import React, { useState, useEffect, useCallback } from 'react';
import {
  ScrollText,
  Download,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
} from 'lucide-react';
import { getEvents, getEventStats } from '../api/client';
import DataTable from '../components/DataTable';
import FilterBar from '../components/FilterBar';

export default function Events() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [totalEvents, setTotalEvents] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [logonTypeFilter, setLogonTypeFilter] = useState('');

  const fetchEventsData = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        limit: pageSize,
        offset: (page - 1) * pageSize,
      };
      if (statusFilter) params.status = statusFilter;
      if (logonTypeFilter) params.logon_type = logonTypeFilter;
      if (search) params.username = search;

      const [res, statRes] = await Promise.all([
        getEvents(params),
        getEventStats().catch(() => null),
      ]);

      const items = Array.isArray(res) ? res : res.events || res.items || [];
      setEvents(items);
      setTotalEvents(res.total ?? items.length);
      if (statRes) setStats(statRes);
    } catch (err) {
      console.error('Failed to load events:', err);
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, logonTypeFilter, search]);

  useEffect(() => {
    fetchEventsData();
  }, [fetchEventsData]);

  const handleExportCsv = () => {
    if (events.length === 0) return;

    const headers = [
      'Timestamp',
      'Agent ID',
      'Event ID',
      'Status',
      'Username',
      'Domain',
      'Logon Type',
      'Source IP',
    ];
    const rows = events.map((e) => [
      e.timestamp,
      e.agent_id,
      e.event_id,
      e.status,
      e.username,
      e.domain || '',
      e.logon_type || '',
      e.source_ip || '',
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sysmon_events_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const columns = [
    {
      key: 'timestamp',
      label: 'Timestamp',
      sortable: true,
      width: '180px',
      render: (val) => (val ? new Date(val).toLocaleString() : '—'),
    },
    {
      key: 'status',
      label: 'Status',
      width: '110px',
      render: (val) => {
        const isSuccess = val === 'SUCCESS' || val === 0;
        return (
          <span className={`status-badge-pill ${isSuccess ? 'success' : 'failure'}`}>
            {isSuccess ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
            {isSuccess ? 'SUCCESS' : 'FAILURE'}
          </span>
        );
      },
    },
    {
      key: 'event_id',
      label: 'Event ID',
      width: '100px',
      render: (val) => <span className="mono-badge">{val || '4624'}</span>,
    },
    {
      key: 'username',
      label: 'User Account',
      render: (val, row) => (
        <div>
          <span className="font-medium text-heading">{val || 'SYSTEM'}</span>
          {row.domain && <span className="text-xs text-muted block">@{row.domain}</span>}
        </div>
      ),
    },
    {
      key: 'logon_type',
      label: 'Logon Type',
      width: '120px',
      render: (val) => {
        const types = {
          2: 'Interactive',
          3: 'Network',
          7: 'Unlock',
          10: 'Remote (RDP)',
        };
        return (
          <span className="text-xs text-secondary">
            {val} {types[val] ? `(${types[val]})` : ''}
          </span>
        );
      },
    },
    {
      key: 'source_ip',
      label: 'Source IP',
      render: (val) => <code className="mono-badge">{val || '127.0.0.1'}</code>,
    },
    {
      key: 'agent_id',
      label: 'Agent ID',
      render: (val) => <span className="text-xs text-muted font-mono">{val}</span>,
    },
  ];

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Event Logs</h1>
          <p className="page-subtitle">Raw telemetry stream & authentication audits</p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            className="btn-secondary"
            onClick={handleExportCsv}
            disabled={events.length === 0}
          >
            <Download size={14} /> Export CSV
          </button>
          <button type="button" className="btn-secondary" onClick={fetchEventsData}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Filter by username or IP..."
        filters={[
          {
            id: 'status',
            label: 'All Outcomes',
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { value: 'SUCCESS', label: 'SUCCESS (Logon OK)' },
              { value: 'FAILURE', label: 'FAILURE (Failed Auth)' },
            ],
          },
          {
            id: 'logon_type',
            label: 'All Logon Types',
            value: logonTypeFilter,
            onChange: setLogonTypeFilter,
            options: [
              { value: '2', label: 'Type 2: Interactive (Console)' },
              { value: '3', label: 'Type 3: Network (SMB/RPC)' },
              { value: '10', label: 'Type 10: RemoteDesktop (RDP)' },
            ],
          },
        ]}
        onReset={() => {
          setSearch('');
          setStatusFilter('');
          setLogonTypeFilter('');
          setPage(1);
        }}
      />

      {/* Event Logs Table */}
      <DataTable
        columns={columns}
        data={events}
        loading={loading}
        emptyMessage="No security events recorded matching criteria."
        pagination={{
          page,
          pageSize,
          total: totalEvents,
          onPageChange: setPage,
        }}
      />
    </div>
  );
}
