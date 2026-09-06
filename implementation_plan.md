# Sysmon → Open-Source Security Platform for Startups

## Vision & Background

You've already built a solid foundation: a telemetry ingestion pipeline (`agent → FastAPI backend → Kafka → ClickHouse`) that collects host metrics, network state, and Windows Security Event logs. The goal is to **evolve this into a full-featured, open-source security monitoring platform** — a credible open alternative to CrowdStrike, ManageEngine, and Microsoft Sentinel — specifically designed for early-stage startups that can't afford enterprise pricing.

The strategy is the **Open-Core Model** (proven by Wazuh, Grafana, and GitLab): a fully open-source Community Edition that startups adopt and love, with a cloud-hosted Enterprise tier for monetization later.

---

## Open Questions

> [!IMPORTANT]
> **Q1 — Scope of this phase**: Do you want to build the entire platform (agent + backend + frontend dashboard) in this phase, or focus first on the backend/detection engine and a polished frontend, leaving cross-platform agent improvements for later?

> [!IMPORTANT]
> **Q2 — Frontend framework**: Do you want the dashboard built with:
> - **Next.js** (full-stack, SSR, great for later SaaS features), or
> - **Vite + React** (pure SPA, simpler to self-host), or
> - **Plain HTML/CSS/JS** (zero dependencies, maximum portability for open source)?

> [!IMPORTANT]
> **Q3 — Alert delivery**: For the MVP, which alert channels do you want to ship with?
> - Slack webhooks only
> - Slack + Discord + Email (SMTP)
> - All of the above + PagerDuty

> [!IMPORTANT]
> **Q4 — Detection rules format**: Should detection rules be:
> - **YAML files** (human-readable, easy contributions from the community — like Sigma rules)
> - **Python plugins** (more powerful but harder to contribute to)
> - **Hybrid**: YAML for simple threshold rules, Python for complex behavioral ones?

---

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         SYSMON PLATFORM                          │
├─────────────────┬────────────────────┬───────────────────────────┤
│   AGENT LAYER   │   INGESTION LAYER  │     ANALYTICS LAYER       │
│                 │                    │                            │
│  agent/         │  backend/          │  worker/                  │
│  ├─ collectors/ │  ├─ api/v1/        │  ├─ detection/            │
│  │  ├─ network  │  │  ├─ transport   │  │  ├─ engine.py          │
│  │  ├─ platform │  │  ├─ health      │  │  └─ rules/ (YAML)      │
│  │  ├─ process  │  │  └─ agents      │  ├─ alerting/             │
│  │  └─ system   │  ├─ config/        │  │  ├─ slack.py           │
│  ├─ utils/      │  ├─ services/      │  │  ├─ discord.py         │
│  └─ main.py     │  └─ main.py        │  │  └─ email.py           │
│                 │                    │  ├─ db/ch_client.py        │
│                 │                    │  └─ main.py                │
├─────────────────┴────────────────────┴───────────────────────────┤
│                      FRONTEND DASHBOARD                           │
│  dashboard/                                                        │
│  ├─ Overview (live threat feed, active agents, alert count)       │
│  ├─ Devices (asset inventory with OS, IP, last seen)              │
│  ├─ Threats (fired detection rules with severity + timeline)      │
│  ├─ Events (raw security event log with search/filter)            │
│  ├─ Rules (view/manage detection rules)                           │
│  └─ Settings (webhook config, retention, agent tokens)            │
├───────────────────────────────────────────────────────────────────┤
│                     INFRASTRUCTURE                                 │
│  infra/                                                            │
│  ├─ kafka/docker-compose.yaml                                      │
│  ├─ clickhouse/docker-compose.yaml                                 │
│  ├─ redis/docker-compose.yaml                                      │
│  └─ docker-compose.full.yaml  ← NEW: one-command deployment       │
└───────────────────────────────────────────────────────────────────┘
```

---

## Proposed Changes

### Phase 1 — Detection Engine (Core Value Differentiator)

The most important thing that separates a "logging tool" from a "security tool" is **automated threat detection**. We build a rule-based detection engine inside the worker.

#### [NEW] `worker/detection/engine.py`
- Loads all YAML rules from `worker/detection/rules/`
- After each Kafka batch is parsed, runs every rule against the buffered events
- Fires alerts via the alerting module when a rule matches
- Supports rule conditions: `threshold`, `pattern_match`, `time_window`

#### [NEW] `worker/detection/rules/` (YAML rule files)
Pre-packaged detection rules shipped with the platform:

| Rule File | Description | Severity |
|---|---|---|
| `brute_force.yaml` | ≥5 failed logins in 60s from same IP | CRITICAL |
| `after_hours_login.yaml` | Successful login between 10PM–6AM | HIGH |
| `new_device_seen.yaml` | First-ever login from an unrecognized agent_id | MEDIUM |
| `privileged_account_login.yaml` | Login by accounts in admin group | HIGH |
| `multiple_ip_login.yaml` | Same user authenticates from 2+ IPs in 5 min | CRITICAL |
| `off_hours_service_start.yaml` | Service account login outside business hours | MEDIUM |
| `repeated_logon_type_change.yaml` | User switches logon type rapidly (lateral movement indicator) | HIGH |

#### [NEW] `worker/alerting/`
- `slack.py` — POST to Slack Incoming Webhook with rich Block Kit formatting
- `discord.py` — POST to Discord webhook
- `email.py` — SMTP alert via `smtplib` (optional, env-configured)
- `dispatcher.py` — Routes alerts from engine to configured channels

---

### Phase 2 — Backend Enhancements

#### [MODIFY] [`backend/main.py`](file:///c:/Users/TALHA/Desktop/Workspace/sysmon/backend/main.py)
- Add `/health` endpoint for agent connectivity checks
- Add `/api/v1/agents` endpoint to list registered agents
- Add agent authentication via bearer tokens (stored in Redis)

#### [NEW] `backend/api/v1/alerts.py`
- `GET /api/v1/alerts` — paginated, filterable threat alerts from ClickHouse
- `GET /api/v1/alerts/{id}` — single alert detail

#### [NEW] `backend/api/v1/devices.py`
- `GET /api/v1/devices` — latest device snapshot per agent
- `GET /api/v1/devices/{agent_id}` — device history

#### [NEW] `backend/api/v1/events.py`
- `GET /api/v1/events` — searchable, paginated raw security events

#### [NEW] `backend/api/v1/rules.py`
- `GET /api/v1/rules` — list all detection rules with metadata
- `PUT /api/v1/rules/{name}/toggle` — enable/disable a rule

---

### Phase 3 — ClickHouse Schema Expansion

#### [MODIFY] [`worker/db/ch_client.py`](file:///c:/Users/TALHA/Desktop/Workspace/sysmon/worker/db/ch_client.py)
Add two new tables:

**`ALERTS` table** — Fired detections:
```sql
CREATE TABLE IF NOT EXISTS ALERTS (
    alert_id     UUID DEFAULT generateUUIDv4(),
    rule_name    String,
    severity     Enum8('LOW'=1, 'MEDIUM'=2, 'HIGH'=3, 'CRITICAL'=4),
    agent_id     String,
    triggered_at DateTime64(3, 'UTC'),
    context      String,   -- JSON snapshot of the triggering events
    resolved     UInt8 DEFAULT 0
) ENGINE = MergeTree()
ORDER BY (triggered_at, severity, agent_id);
```

**`PROCESSES` table** — Process execution events (future agent expansion):
```sql
CREATE TABLE IF NOT EXISTS PROCESSES (
    agent_id    String,
    timestamp   DateTime64(3, 'UTC'),
    pid         UInt32,
    ppid        UInt32,
    name        String,
    cmdline     String,
    user        String,
    cpu_percent Float32,
    mem_percent Float32
) ENGINE = MergeTree()
ORDER BY (agent_id, timestamp);
```

---

### Phase 4 — Frontend Dashboard

#### [NEW] `dashboard/` — React/Next.js Security Dashboard

A stunning, dark-mode security operations dashboard with 6 views:

**1. Overview Page** (`/`)
- Real-time threat feed (live WebSocket or polling)
- KPI cards: Active Agents, Alerts Today, Failed Logins, Critical Threats
- Threat severity timeline chart (last 24h)
- Top 5 most-triggered rules

**2. Devices Page** (`/devices`)
- Asset inventory table: hostname, IP, OS, arch, last seen, status (online/offline)
- Click-through to device detail with login history

**3. Threats Page** (`/threats`)
- List of all fired alerts with: rule name, severity badge, agent, timestamp, status (open/resolved)
- Filter by severity, date range, agent
- One-click "Mark Resolved"

**4. Events Page** (`/events`)
- Raw security event log (Windows 4624/4625)
- Search by username, IP, logon type
- Export to CSV

**5. Rules Page** (`/rules`)
- Table of all detection rules with: name, description, severity, enabled/disabled toggle
- Rule details drawer (shows YAML condition logic)

**6. Settings Page** (`/settings`)
- Configure Slack/Discord webhook URLs
- Set data retention policy
- Generate agent API tokens

---

### Phase 5 — One-Command Deployment

#### [NEW] `docker-compose.full.yaml` (root level)
Single file that spins up the entire stack:
```
services: kafka, zookeeper, clickhouse, redis, backend, worker, dashboard
```

#### [NEW] `Makefile`
```makefile
up:    docker compose -f docker-compose.full.yaml up -d
down:  docker compose -f docker-compose.full.yaml down
logs:  docker compose -f docker-compose.full.yaml logs -f
```

#### [NEW] `.env.example` (root level)
Template with all required environment variables and inline documentation.

---

### Phase 6 — Open-Source Readiness

#### [MODIFY] [`README.md`](file:///c:/Users/TALHA/Desktop/Workspace/sysmon/README.md)
Full rewrite as a professional open-source project README:
- Badges (license, stars, version)
- Compelling hero section with screenshots
- One-command quick start
- Architecture diagram
- Contributing guide link
- Comparison table vs. paid tools

#### [NEW] `CONTRIBUTING.md`
- How to write custom detection rules (YAML schema reference)
- Development setup guide
- PR checklist

#### [NEW] `SECURITY.md`
- Responsible disclosure policy

#### [NEW] `docs/` — Architecture & rule authoring docs

---

## Implementation Order

```
Week 1: Detection Engine + Alerting (Phase 1)
         → Most impactful for "security tool" credibility
Week 2: Backend API Expansion (Phase 2) + Schema (Phase 3)
         → Enables the dashboard to have real data
Week 3: Frontend Dashboard (Phase 4)
         → The visual wow factor for GitHub/HN
Week 4: Deployment + Open-Source polish (Phase 5 + 6)
         → Ready to post on GitHub / Hacker News
```

---

## Verification Plan

### Automated Tests
- `pytest worker/tests/` — Unit tests for detection engine rule evaluation
- `pytest backend/tests/` — Integration tests for new API endpoints (using FastAPI TestClient)

### Manual Verification
- Deploy full stack with `docker compose -f docker-compose.full.yaml up`
- Run agent on a Windows machine, confirm telemetry appears in the dashboard
- Trigger a brute-force rule by making 5+ failed login attempts, confirm Slack alert fires
- Verify all 6 dashboard pages render with real data
