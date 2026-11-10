/**
 * dashboard/src/api/client.js
 *
 * Centralised HTTP client for the Sysmon REST API.
 * Base URL is configurable via VITE_API_URL env variable.
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
let csrfToken = null;

export const setCsrfToken = (token) => {
  csrfToken = token;
};

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const method = (options.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    if (
      res.status === 401 &&
      !['/api/v1/auth/status', '/api/v1/auth/login', '/api/v1/auth/setup'].includes(path)
    ) {
      setCsrfToken(null);
      window.dispatchEvent(new Event('sysmon-auth-expired'));
    }
    throw new Error(body.detail || `API error ${res.status}`);
  }

  return res.json();
}

// ── Administrator Authentication ────────────────────────────
export const getAuthStatus = () => request('/api/v1/auth/status');

export const getCurrentAdmin = async () => {
  const result = await request('/api/v1/auth/me');
  setCsrfToken(result.csrf_token);
  return result.user;
};

export const setupAdmin = async (username, password) => {
  const result = await request('/api/v1/auth/setup', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  setCsrfToken(result.csrf_token);
  return result.user;
};

export const loginAdmin = async (username, password) => {
  const result = await request('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  setCsrfToken(result.csrf_token);
  return result.user;
};

export const logoutAdmin = async () => {
  await request('/api/v1/auth/logout', { method: 'POST' });
  setCsrfToken(null);
};

export const changeAdminPassword = async (newPassword) => {
  await request('/api/v1/auth/password', {
    method: 'POST',
    body: JSON.stringify({ new_password: newPassword }),
  });
  setCsrfToken(null);
};

// ── Alerts ──────────────────────────────────────────────────
export const getAlerts = (params = {}) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') qs.append(k, v);
  });
  return request(`/api/v1/alerts?${qs}`);
};

export const getAlertStats = () => request('/api/v1/alerts/stats');

export const getAlertById = (id) => request(`/api/v1/alerts/${id}`);

export const resolveAlert = (id, resolved = true) =>
  request(`/api/v1/alerts/${id}/resolve`, {
    method: 'PATCH',
    body: JSON.stringify({ resolved }),
  });

// ── Devices ─────────────────────────────────────────────────
export const getDevices = () => request('/api/v1/devices');

export const getDeviceStats = () => request('/api/v1/devices/stats');

export const getDeviceById = (agentId) => request(`/api/v1/devices/${agentId}`);

export const getDeviceHistory = (agentId, limit = 50) =>
  request(`/api/v1/devices/${agentId}/history?limit=${limit}`);

// ── Events ──────────────────────────────────────────────────
export const getEvents = (params = {}) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') qs.append(k, v);
  });
  return request(`/api/v1/events?${qs}`);
};

export const getEventStats = () => request('/api/v1/events/stats');

// ── Rules ───────────────────────────────────────────────────
export const getRules = () => request('/api/v1/rules');

export const getRuleByName = (name) => request(`/api/v1/rules/${name}`);

export const toggleRule = (name, enabled) =>
  request(`/api/v1/rules/${name}/toggle`, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });

// ── Agents / Tokens ─────────────────────────────────────────
export const getAgents = () => request('/api/v1/agents');

export const getAgentTokens = () => request('/api/v1/agents/tokens');

export const createAgentToken = (description = 'Dashboard Token') =>
  request('/api/v1/agents/token', {
    method: 'POST',
    body: JSON.stringify({ description }),
  });

export const revokeAgentToken = (token) =>
  request(`/api/v1/agents/tokens/${token}`, { method: 'DELETE' });

// ── Health ──────────────────────────────────────────────────
export const getHealth = () => request('/health');
