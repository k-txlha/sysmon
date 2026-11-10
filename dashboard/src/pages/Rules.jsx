import React, { useState, useEffect, useCallback } from 'react';
import {
  BookOpen,
  ToggleLeft,
  ToggleRight,
  RefreshCw,
  Eye,
  Sliders,
  CheckCircle2,
  FileCode2,
} from 'lucide-react';
import { getRules, getRuleByName, toggleRule } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import DataTable from '../components/DataTable';
import FilterBar from '../components/FilterBar';
import DetailDrawer from '../components/DetailDrawer';

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [togglingRule, setTogglingRule] = useState(null);

  // Drawer state
  const [selectedRule, setSelectedRule] = useState(null);
  const [drawerLoading, setDrawerLoading] = useState(false);

  const fetchRulesData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getRules();
      setRules(Array.isArray(res) ? res : res.rules || []);
    } catch (err) {
      console.error('Failed to load detection rules:', err);
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRulesData();
  }, [fetchRulesData]);

  const handleToggle = async (rule, e) => {
    if (e) e.stopPropagation();
    setTogglingRule(rule.name);
    try {
      const newEnabled = !rule.enabled;
      await toggleRule(rule.name, newEnabled);
      setRules((prev) =>
        prev.map((r) => (r.name === rule.name ? { ...r, enabled: newEnabled } : r))
      );
      if (selectedRule?.name === rule.name) {
        setSelectedRule((prev) => ({ ...prev, enabled: newEnabled }));
      }
    } catch (err) {
      console.error('Failed to toggle detection rule:', err);
    } finally {
      setTogglingRule(null);
    }
  };

  const handleOpenDetail = async (rule) => {
    setSelectedRule(rule);
    setDrawerLoading(true);
    try {
      const detail = await getRuleByName(rule.name);
      setSelectedRule(detail || rule);
    } catch (err) {
      console.error('Failed to fetch rule YAML:', err);
    } finally {
      setDrawerLoading(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      !search ||
      r.name?.toLowerCase().includes(search.toLowerCase()) ||
      r.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSev = !severityFilter || r.severity === severityFilter;
    return matchesSearch && matchesSev;
  });

  const columns = [
    {
      key: 'enabled',
      label: 'Active',
      width: '90px',
      render: (val, row) => (
        <button
          type="button"
          className={`btn-toggle-switch ${val ? 'active' : ''}`}
          onClick={(e) => handleToggle(row, e)}
          disabled={togglingRule === row.name}
          title={val ? 'Disable Rule' : 'Enable Rule'}
        >
          {togglingRule === row.name ? (
            <RefreshCw size={14} className="animate-spin" />
          ) : val ? (
            <ToggleRight size={22} className="text-accent-green" />
          ) : (
            <ToggleLeft size={22} className="text-muted" />
          )}
        </button>
      ),
    },
    {
      key: 'name',
      label: 'Rule Name',
      sortable: true,
      render: (val, row) => (
        <div>
          <div className="font-semibold text-heading">{val}</div>
          <div className="text-xs text-muted line-clamp-1">{row.description}</div>
        </div>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      width: '120px',
      sortable: true,
      render: (val) => <SeverityBadge severity={val} />,
    },
    {
      key: 'condition_type',
      label: 'Condition Engine',
      render: (val, row) => (
        <span className="mono-badge">
          {val || row.condition?.type || 'threshold'}
        </span>
      ),
    },
    {
      key: 'tags',
      label: 'Tags',
      render: (val) => (
        <div className="tag-group">
          {(val || []).map((t) => (
            <span key={t} className="tag-pill">
              #{t}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'actions',
      label: '',
      width: '60px',
      render: (_, row) => (
        <button
          type="button"
          className="btn-icon"
          title="Inspect Rule YAML"
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
          <h1 className="page-title">Detection Rules Manager</h1>
          <p className="page-subtitle">Configure real-time heuristics, thresholds, and Sigma rules</p>
        </div>
        <button type="button" className="btn-secondary" onClick={fetchRulesData}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Filter rules by name or description..."
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
        ]}
        onReset={() => {
          setSearch('');
          setSeverityFilter('');
        }}
      />

      {/* Rules Table */}
      <DataTable
        columns={columns}
        data={filteredRules}
        loading={loading}
        emptyMessage="No detection rules match criteria."
        onRowClick={handleOpenDetail}
      />

      {/* Rule Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedRule}
        onClose={() => setSelectedRule(null)}
        title={selectedRule?.name || 'Detection Rule Specification'}
        subtitle={`Severity: ${selectedRule?.severity || 'MEDIUM'}`}
        width="620px"
      >
        {selectedRule && (
          <div className="drawer-content-stack">
            <div className="flex-between">
              <SeverityBadge severity={selectedRule.severity} />
              <button
                type="button"
                className={`btn-status ${selectedRule.enabled ? 'resolved' : 'open'}`}
                onClick={(e) => handleToggle(selectedRule, e)}
                disabled={togglingRule === selectedRule.name}
              >
                {selectedRule.enabled ? 'Active / Enabled' : 'Disabled'}
              </button>
            </div>

            <div className="drawer-section mt-4">
              <h4 className="section-title">Description</h4>
              <p className="text-secondary text-sm">{selectedRule.description || 'No description'}</p>
            </div>

            {/* Condition Info */}
            <div className="drawer-section">
              <h4 className="section-title">Condition Logic</h4>
              <div className="info-box-full font-mono text-xs">
                {JSON.stringify(selectedRule.condition || {}, null, 2)}
              </div>
            </div>

            {/* Raw YAML / Source View */}
            <div className="drawer-section">
              <div className="flex-between">
                <h4 className="section-title">Raw Rule Definition</h4>
                <FileCode2 size={14} className="text-muted" />
              </div>
              <pre className="code-block">
                {selectedRule.raw_yaml ||
                  selectedRule.yaml_content ||
                  JSON.stringify(selectedRule, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
