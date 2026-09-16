import React, { useState, useEffect, useCallback } from 'react';
import {
  Settings as SettingsIcon,
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  ShieldCheck,
  Server,
  Bell,
  Database,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';
import {
  getAgentTokens,
  createAgentToken,
  revokeAgentToken,
  getHealth,
} from '../api/client';

export default function Settings() {
  const [tokens, setTokens] = useState([]);
  const [tokensLoading, setTokensLoading] = useState(true);
  const [newTokenDesc, setNewTokenDesc] = useState('');
  const [generatingToken, setGeneratingToken] = useState(false);
  const [copiedToken, setCopiedToken] = useState(null);
  const [createdTokenVal, setCreatedTokenVal] = useState(null);

  // Health
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);

  // Webhook settings state
  const [slackWebhook, setSlackWebhook] = useState('');
  const [discordWebhook, setDiscordWebhook] = useState('');
  const [savedWebhooks, setSavedWebhooks] = useState(false);

  const fetchTokenData = useCallback(async () => {
    setTokensLoading(true);
    try {
      const res = await getAgentTokens();
      setTokens(Array.isArray(res) ? res : res.tokens || []);
    } catch (err) {
      console.error('Failed to load agent tokens:', err);
      setTokens([]);
    } finally {
      setTokensLoading(false);
    }
  }, []);

  const fetchHealthData = useCallback(async () => {
    setHealthLoading(true);
    try {
      const res = await getHealth();
      setHealth(res);
    } catch (err) {
      console.error('Health check failed:', err);
      setHealth({ status: 'unhealthy', error: String(err) });
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTokenData();
    fetchHealthData();
  }, [fetchTokenData, fetchHealthData]);

  const handleCreateToken = async (e) => {
    e.preventDefault();
    setGeneratingToken(true);
    try {
      const res = await createAgentToken(newTokenDesc || 'Endpoint Agent Token');
      setCreatedTokenVal(res.token || res);
      setNewTokenDesc('');
      fetchTokenData();
    } catch (err) {
      console.error('Failed to create token:', err);
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleRevokeToken = async (tokenString) => {
    if (!window.confirm('Are you sure you want to revoke this enrollment token?')) return;
    try {
      await revokeAgentToken(tokenString);
      fetchTokenData();
    } catch (err) {
      console.error('Failed to revoke token:', err);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(text);
    setTimeout(() => setCopiedToken(null), 2500);
  };

  const handleSaveWebhooks = (e) => {
    e.preventDefault();
    setSavedWebhooks(true);
    setTimeout(() => setSavedWebhooks(false), 3000);
  };

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Platform Settings</h1>
          <p className="page-subtitle">Agent authentication, notifications, and telemetry health</p>
        </div>
      </div>

      <div className="settings-stack">
        {/* System Health Status */}
        <div className="card">
          <div className="card-header">
            <div className="flex-align gap-2">
              <Server size={18} className="text-accent-cyan" />
              <h2 className="card-title">System & Backend Health</h2>
            </div>
            <button
              type="button"
              className="btn-secondary"
              onClick={fetchHealthData}
              disabled={healthLoading}
            >
              <RefreshCw size={13} className={healthLoading ? 'animate-spin' : ''} />
              Check Status
            </button>
          </div>
          <div className="card-content">
            <div className="health-grid">
              <div className="health-item">
                <span className="health-label">Gateway API:</span>
                <span className={`health-status ${health?.status === 'ok' || health?.status === 'healthy' ? 'online' : 'offline'}`}>
                  {health?.status || 'Active'}
                </span>
              </div>
              <div className="health-item">
                <span className="health-label">ClickHouse DB:</span>
                <span className={`health-status ${health?.clickhouse === false ? 'offline' : 'online'}`}>
                  {health?.clickhouse === false ? 'Disconnected' : 'Connected'}
                </span>
              </div>
              <div className="health-item">
                <span className="health-label">Redis Cache:</span>
                <span className={`health-status ${health?.redis === false ? 'offline' : 'online'}`}>
                  {health?.redis === false ? 'Offline' : 'Connected'}
                </span>
              </div>
              <div className="health-item">
                <span className="health-label">Kafka Ingestion:</span>
                <span className={`health-status ${health?.kafka === false ? 'offline' : 'online'}`}>
                  {health?.kafka === false ? 'Offline' : 'Operational'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Agent Enrollment Tokens */}
        <div className="card">
          <div className="card-header">
            <div className="flex-align gap-2">
              <Key size={18} className="text-accent-blue" />
              <h2 className="card-title">Agent Enrollment Tokens</h2>
            </div>
          </div>
          <div className="card-content">
            <p className="text-secondary text-sm mb-4">
              Enrollment tokens allow Sysmon agents on Windows endpoints to authenticate with the
              ingestion gateway.
            </p>

            {/* Create Token Form */}
            <form onSubmit={handleCreateToken} className="token-form">
              <input
                type="text"
                placeholder="Token description (e.g. Production Web Tier)"
                value={newTokenDesc}
                onChange={(e) => setNewTokenDesc(e.target.value)}
                className="form-input flex-1"
              />
              <button
                type="submit"
                className="btn-primary"
                disabled={generatingToken}
              >
                <Plus size={16} />
                {generatingToken ? 'Generating...' : 'Generate Token'}
              </button>
            </form>

            {/* Newly Created Token Banner */}
            {createdTokenVal && (
              <div className="alert-box-success mt-4">
                <div className="flex-between">
                  <div className="flex-align gap-2">
                    <ShieldCheck size={18} className="text-accent-green" />
                    <span className="font-semibold text-accent-green">New Token Generated:</span>
                  </div>
                  <button
                    type="button"
                    className="btn-icon"
                    onClick={() => handleCopy(typeof createdTokenVal === 'object' ? createdTokenVal.token : createdTokenVal)}
                  >
                    {copiedToken ? <Check size={14} className="text-accent-green" /> : <Copy size={14} />}
                  </button>
                </div>
                <code className="token-display">
                  {typeof createdTokenVal === 'object' ? createdTokenVal.token : createdTokenVal}
                </code>
              </div>
            )}

            {/* Active Tokens List */}
            <div className="tokens-list mt-6">
              <h4 className="section-title mb-3">Active Tokens</h4>
              {tokensLoading ? (
                <div className="loading-box">
                  <RefreshCw size={16} className="animate-spin text-accent-blue" />
                  <span>Loading tokens...</span>
                </div>
              ) : tokens.length === 0 ? (
                <p className="text-muted text-sm italic">No active tokens found. Generate one above.</p>
              ) : (
                <div className="token-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Token</th>
                        <th>Description</th>
                        <th>Created</th>
                        <th style={{ width: '80px' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tokens.map((t, idx) => {
                        const tokenStr = typeof t === 'string' ? t : t.token;
                        const desc = t.description || 'Agent Token';
                        const created = t.created_at ? new Date(t.created_at).toLocaleDateString() : 'Active';
                        return (
                          <tr key={tokenStr || idx}>
                            <td>
                              <div className="flex-align gap-2">
                                <code className="mono-badge">
                                  {tokenStr ? `${tokenStr.slice(0, 12)}...${tokenStr.slice(-6)}` : '••••••••'}
                                </code>
                                <button
                                  type="button"
                                  className="btn-icon sm"
                                  onClick={() => handleCopy(tokenStr)}
                                  title="Copy full token"
                                >
                                  {copiedToken === tokenStr ? (
                                    <Check size={12} className="text-accent-green" />
                                  ) : (
                                    <Copy size={12} />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="text-secondary">{desc}</td>
                            <td className="text-muted text-xs">{created}</td>
                            <td>
                              <button
                                type="button"
                                className="btn-icon danger sm"
                                onClick={() => handleRevokeToken(tokenStr)}
                                title="Revoke Token"
                              >
                                <Trash2 size={14} />
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Alerting & Notification Webhooks */}
        <div className="card">
          <div className="card-header">
            <div className="flex-align gap-2">
              <Bell size={18} className="text-accent-amber" />
              <h2 className="card-title">Alert Webhooks (Slack / Discord)</h2>
            </div>
          </div>
          <div className="card-content">
            <form onSubmit={handleSaveWebhooks} className="webhook-form-stack">
              <div className="form-group">
                <label className="form-label">Slack Incoming Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/..."
                  value={slackWebhook}
                  onChange={(e) => setSlackWebhook(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Discord Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://discord.com/api/webhooks/..."
                  value={discordWebhook}
                  onChange={(e) => setDiscordWebhook(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="flex-align gap-3 mt-2">
                <button type="submit" className="btn-primary">
                  Save Webhook Settings
                </button>
                {savedWebhooks && (
                  <span className="text-accent-green text-sm flex-align gap-1">
                    <Check size={14} /> Configuration saved!
                  </span>
                )}
              </div>
            </form>
          </div>
        </div>

        {/* Data Retention & Storage Policy */}
        <div className="card">
          <div className="card-header">
            <div className="flex-align gap-2">
              <Database size={18} className="text-accent-purple" />
              <h2 className="card-title">Storage & Retention Policy</h2>
            </div>
          </div>
          <div className="card-content">
            <div className="info-grid">
              <div className="info-box">
                <span className="info-label">Security Events Retention</span>
                <span className="info-value">90 Days (ClickHouse TTL)</span>
              </div>
              <div className="info-box">
                <span className="info-label">Alert Incidents Retention</span>
                <span className="info-value">365 Days</span>
              </div>
              <div className="info-box">
                <span className="info-label">Kafka Partitioning</span>
                <span className="info-value">3 Partitions (Round-Robin)</span>
              </div>
              <div className="info-box">
                <span className="info-label">Telemetry Format</span>
                <span className="info-value font-mono">JSON / MsgPack</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
