# 🛡️ Sysmon — Open-Source EDR & Security Telemetry Platform

A high-performance, modular, and cloud-ready **Endpoint Detection & Response (EDR)** and Security Telemetry platform. Sysmon collects cross-platform endpoint telemetry, guarantees resilience with offline local disk buffering, validates events against strict EDR Event Envelope data contracts, streams through Apache Kafka, performs high-throughput analytical batching in ClickHouse, executes real-time threat detection with YAML rules, dispatches multi-channel alerts (Slack, Discord, Email), and provides a React-based security operations dashboard and REST API.

---

## 📋 Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Sysmon Agent                              │
│                                                                        │
│   ┌────────────────────┐   ┌───────────────────┐   ┌───────────────┐   │
│   │  SystemCollector   │   │    OSCollector    │   │ Agent Health  │   │
│   │ (CPU, RAM, Sockets)│   │ (Windows / Linux) │   │ (RSS, Queues) │   │
│   └─────────┬──────────┘   └─────────┬─────────┘   └───────┬───────┘   │
│             │                        │                     │           │
│             └────────────────────────┼─────────────────────┘           │
│                                      ▼                                 │
│                         ┌──────────────────────────┐                   │
│                         │    TelemetryAssembler    │                   │
│                         │ (EventEnvelope Packaging)│                   │
│                         └────────────┬─────────────┘                   │
│                                      ▼                                 │
│                         ┌──────────────────────────┐                   │
│                         │   Local Bounded Buffer   │                   │
│                         │  (SQLite WAL FIFO Queue) │                   │
│                         └────────────┬─────────────┘                   │
└──────────────────────────────────────┼─────────────────────────────────┘
                                       │ POST /api/v1/telemetry
                                       │ (Strict Schema + Token Auth + Heartbeat)
                                       ▼
                          ┌──────────────────────────┐
                          │     Backend Gateway      │
                          │        (FastAPI)         │
                          └────────────┬─────────────┘
                                       │ Produce EventEnvelopes (Concurrent Batch)
                                       ▼
                          ┌──────────────────────────┐
                          │       Apache Kafka       │
                          │     (telemetry_data)     │
                          └────────────┬─────────────┘
                                       │ Consume Streams
                                       ▼
                          ┌──────────────────────────┐
                          │      Worker Service      │
                          │  (Dual-Trigger Batcher)  │
                          └─────┬──────────────┬─────┘
                                │              │
           ┌────────────────────┘              └────────────────────┐
           ▼                                                        ▼
┌─────────────────────────┐                              ┌─────────────────────────┐
│    Detection Engine     │                              │   ClickHouse Database   │
│  (YAML Rule Evaluator)  │                              │ (DEVICES, EVENTS, ALERTS│
└────────────┬────────────┘                              │      AGENT_HEALTH)      │
             │                                           └────────────▲────────────┘
             ▼ Fired Alerts                                           │ Query Analytics
┌─────────────────────────┐                              ┌────────────┴────────────┐
│    Alert Dispatcher     │                              │   ClickHouse Service    │
│ (Slack, Discord, Email) ├─── Persist Alerts ──────────►│    & REST API Layer     │
└─────────────────────────┘                              └────────────▲────────────┘
                                                                      │
                                                         ┌────────────┴────────────┐
                                                         │   Frontend Dashboard    │
                                                         │     (React / Vite)      │
                                                         └─────────────────────────┘
```

---

## 📁 Repository Layout

```
├── agent/                         # Endpoint Telemetry Collector & Sensor
│   ├── collectors/                # Specialized metric & audit collectors
│   │   ├── base.py                # Abstract base OS collector interface
│   │   ├── common.py              # Cross-platform CPU, RAM, process & network metrics
│   │   ├── windows.py             # Windows platform info & Security EventLog parser (4624/4625)
│   │   ├── linux.py               # Linux auth log parser (/var/log/auth.log, journald)
│   │   └── darwin.py              # macOS system & auth collector
│   ├── models/                    # Data contracts & Pydantic schemas
│   │   └── envelope.py            # Standardized EventEnvelope & AgentHealth schemas
│   ├── utils/                     # Transport, buffering, and logging utilities
│   │   ├── assembler.py           # Standardized EventEnvelope packaging
│   │   ├── buffer.py              # SQLite WAL-mode offline bounded disk queue
│   │   ├── config.py              # Strongly-typed environment configuration loader
│   │   ├── logger.py              # Structured logging utility
│   │   └── transport.py           # Resilient HTTP transport with queue drain & backoff
│   ├── tests/                     # Agent test suites (buffer, envelope, assembler, service, enroll)
│   ├── enroll.py                  # Automated bootstrap enrollment client & CLI
│   ├── service.py                 # OS background service manager (systemd & Windows)
│   ├── .env                       # Local agent configuration
│   └── main.py                    # Agent execution daemon & collection loop
│
├── backend/                       # REST API & Telemetry Ingestion Gateway
│   ├── api/v1/                    # Versioned REST endpoints
│   │   ├── agents.py              # Agent tokens, registration & enrollment handshake
│   │   ├── alerts.py              # Alert query, stats & status management
│   │   ├── devices.py             # Host inventory, hardware/OS analytics & health telemetry
│   │   ├── events.py              # Security audit log & raw event queries
│   │   ├── health.py              # System health & dependency status
│   │   ├── rules.py               # Detection rule CRUD & YAML validation
│   │   └── transport.py           # Strict EventEnvelope ingestion endpoint
│   ├── config/                    # Backend configuration
│   │   └── settings.py            # Environment settings & ClickHouse/Kafka/Redis config
│   ├── models/                    # Ingestion data models & batch schemas
│   │   └── envelope.py            # Backend EventEnvelope & IngestionBatchRequest models
│   ├── services/                  # Business logic & query services
│   │   ├── agent_service.py       # Agent token authentication, enrollment & heartbeat tracking
│   │   ├── ch_service.py          # ClickHouse analytical query engine
│   │   └── producer.py            # High-throughput asynchronous Kafka producer service
│   ├── tests/                     # Backend test suite (test_api.py)
│   ├── utils/                     # Backend utilities (logger, rate limiter)
│   ├── .env                       # Backend environment configuration
│   └── main.py                    # FastAPI application entrypoint & ASGI server
│
├── worker/                        # Stream Processing, Detection & Alerting Worker
│   ├── alerting/                  # Modular notification framework
│   │   ├── discord.py             # Discord webhook integration with rich embeds
│   │   ├── dispatcher.py          # Fan-out dispatcher to active channels + ClickHouse
│   │   ├── email.py               # SMTP email dispatcher with HTML templates
│   │   └── slack.py               # Slack webhook integration with Block Kit cards
│   ├── db/                        # Database client & schema definitions
│   │   └── ch_client.py           # ClickHouse bulk insertion client & table schemas
│   ├── detection/                 # Stateful Threat Detection Engine
│   │   ├── rules/                 # Built-in YAML detection rules
│   │   │   ├── after_hours_login.yaml
│   │   │   ├── brute_force.yaml
│   │   │   ├── multiple_ip_login.yaml
│   │   │   ├── new_device_seen.yaml
│   │   │   ├── off_hours_service_start.yaml
│   │   │   ├── privileged_account_login.yaml
│   │   │   └── repeated_logon_type_change.yaml
│   │   ├── engine.py              # Rule evaluator with windowing & threshold tracking
│   │   ├── loader.py              # YAML rule parser and validator
│   │   └── models.py              # Pydantic models for rules, conditions & alerts
│   ├── tests/                     # Worker test suite (test_engine.py)
│   ├── utils/                     # Worker utilities (config, logger)
│   ├── .env                       # Worker environment configuration
│   └── main.py                    # Kafka consumer, envelope normalization & detection loop
│
├── dashboard/                     # Security Operations Frontend UI
│   ├── src/                       # React components, pages & API client
│   │   ├── pages/                 # Overview, Devices, Events, Threats, Rules, Settings
│   │   └── components/            # Reusable UI widgets & data tables
│   ├── package.json               # Frontend dependencies (React, Vite, Lucide)
│   └── index.html                 # Single page application entrypoint
│
├── infra/                         # Infrastructure Service Definitions
│   ├── clickhouse/                # ClickHouse server configuration & compose
│   ├── kafka/                     # Apache Kafka & Zookeeper compose
│   └── redis/                     # Redis cache & rate limiter compose
│
├── pytest.ini                     # Pytest configuration with isolated pythonpath
├── run_tests.py                   # Unified cross-platform test runner
├── requirements.txt               # Unified project dependencies
└── README.md                      # Project documentation
```

---

## ✨ Key Features & Data Contracts

### 1. 📜 Standardized Event Envelope (Phase 0 Data Contract)

Every event transmitted through Sysmon adheres to the strict EDR Event Envelope schema:

```json
{
  "event_id": "c61b24d7-e07b-4029-a1b7-1c64eb37a098",
  "schema_version": 1,
  "tenant_id": "default",
  "host_id": "WORKSTATION-01",
  "agent_id": "WORKSTATION-01",
  "event_type": "security.auth",
  "observed_at": "2026-10-02T12:00:00.000000Z",
  "received_at": "2026-10-02T12:00:00.085000Z",
  "sequence": 142,
  "source": "windows_agent",
  "severity": "medium",
  "data": {
    "event_id": 4625,
    "status": "FAILURE",
    "username": "administrator",
    "domain": "CORP",
    "logon_type": "RemoteInteractive (RDP)",
    "source_ip": "198.51.100.25"
  }
}
```

### 2. 🛡️ Agent Resilience, Local Disk Buffer & Service Management

- **Local Bounded Disk Buffer (`agent/utils/buffer.py`)**: Events are committed to an SQLite WAL queue before delivery. The agent authenticates through the credential-renewal endpoint before sending; during a network outage it continues collection and persists events. Delivery uses batches, exponential backoff with jitter, and honors HTTP `Retry-After`. A batch is removed only when the backend returns an `accepted` acknowledgement containing the exact event IDs.
- **Bounded retention and overflow**: `SIEM_BUFFER_MAX_EVENTS` and `SIEM_BUFFER_MAX_BYTES` bound pending event payloads, and `SIEM_BUFFER_RETENTION_SECONDS` sets their maximum age (7 days by default). At capacity, the documented policy evicts the oldest unacknowledged events to admit a new event; an event larger than the byte limit is rejected. Expiry and overflow increment the dropped counter and emit warnings. Protect the SQLite database and its WAL files with owner-only permissions; use OS full-disk encryption (for example BitLocker or LUKS) when local-disk compromise is in scope. The agent does not implement application-level database encryption.
- **OS Service Management (`agent/service.py`)**: Install, start, stop, and query the agent at boot (Linux `systemd` unit or Windows Task Scheduler task).
- **Automated Bootstrap Enrollment (`agent/enroll.py`)**: Agent exchanges a short-lived, single-use bootstrap token for a permanent credential and backend-assigned agent/tenant identity via `POST /api/v1/agents/enroll`; enrollment saves these values to the local agent configuration.
- **Agent Health Diagnostics (`agent.health`)**: Automatically captures and transmits agent process memory (RSS MB), process CPU usage, local queue depth, and dropped event counters, persisted in ClickHouse `AGENT_HEALTH` table.

### 3. ⚡ Ingestion Gateway & Security Analytics API (`backend/`)

- **Authenticated Ingestion**: Requires an active agent credential, derives identity from the SQLite credential registry, and rejects mismatched `agent_id` or `tenant_id` values. An unreachable backend is treated as temporary and does not invalidate local credentials or queued events; explicit 401/403 responses disable transmission until authentication succeeds again. Remote agent enrollment, telemetry, and renewal require verified HTTPS; loopback HTTP is allowed only for development.
- **Strict Ingestion**: Validates incoming payloads against `EventEnvelope` and `IngestionBatchRequest` schemas; rejects malformed inputs with `HTTP 422`.
- **Durable Batch Acknowledgement**: The gateway acknowledges only after Kafka confirms the records with `acks=all`. Backend receipts and per-agent event IDs make retrying an acknowledged batch idempotent; Kafka records are keyed by `agent_id:event_id`.
- **Server-Side Timestamping**: Adds `received_at` UTC timestamps and records live heartbeats in Redis.
- **Analytical Query Engine**: `ClickHouseQueryService` provides aggregated KPI statistics, device history, agent health diagnostics, and threat analytics.

### 4. 🧠 Real-Time Detection Engine (`worker/detection/`)

- Declarative YAML rules with stateful sliding time windows.
- Built-in detection scenarios:
  - **Brute Force Attacks**: Repeated failed logins within a sliding time window.
  - **After-Hours Logins**: Authentication outside authorized operating hours.
  - **Privileged Account Logins**: Sensitive accounts (`root`, `Administrator`) logging in unexpectedly.
  - **Multiple IP Logins**: Concurrent logins from different IP addresses.
  - **New Device Seen**: First-time host / agent sightings.
  - **Off-Hours Service Execution**: Services starting during maintenance windows.
  - **Logon Type Anomalies**: Rapid switching between interactive and network logon types.

### 5. 📢 Multi-Channel Alert Dispatcher (`worker/alerting/`)

- Dispatches formatted alerts to **Slack** (Block Kit), **Discord** (Embeds), and **Email** (SMTP).
- Persists all fired alerts to ClickHouse `ALERTS` table before dispatch.

---

## 🌐 REST API Reference (`/api/v1`)

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

| Method   | Endpoint                             | Description                                                                |
| -------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `GET`    | `/health`                            | Service health status (Kafka, ClickHouse, Redis)                           |
| `POST`   | `/api/v1/telemetry`                  | Ingest standardized EventEnvelope telemetry (Rate-limited & authenticated) |
| `GET`    | `/api/v1/alerts`                     | Paginated alert list with severity, agent, rule, and status filters        |
| `GET`    | `/api/v1/alerts/stats`               | Aggregated alert breakdown and 24-hour timeline statistics                 |
| `PATCH`  | `/api/v1/alerts/{alert_id}/status`   | Update alert resolution status (`0` = Open, `1` = Resolved)                |
| `GET`    | `/api/v1/devices`                    | Query device inventory, operating system details, and online status        |
| `GET`    | `/api/v1/devices/stats`              | Aggregated device metrics (active hosts, OS distribution)                  |
| `GET`    | `/api/v1/devices/{agent_id}`         | Detailed hardware, network, and health telemetry for a specific device     |
| `GET`    | `/api/v1/devices/{agent_id}/health`  | Query latest health diagnostics report (CPU, RSS, queue depth)             |
| `GET`    | `/api/v1/devices/{agent_id}/history` | Historical telemetry snapshots for an agent                                |
| `GET`    | `/api/v1/events`                     | Query raw security authentication logs with filters and pagination         |
| `GET`    | `/api/v1/rules`                      | List all active detection rules                                            |
| `POST`   | `/api/v1/rules/{rule_name}/toggle`   | Enable or disable a detection rule                                         |
| `GET`    | `/api/v1/agents/tokens`                 | List credential metadata only; plaintext credentials are never listed (administrator session required) |
| `POST`   | `/api/v1/agents/token`                  | Generate a single-use bootstrap token (administrator session and CSRF required) |
| `POST`   | `/api/v1/agents/enroll`                 | Exchange bootstrap token for agent credential and server-assigned identity       |
| `POST`   | `/api/v1/agents/renew`                  | Renew an agent credential using the current credential                           |
| `DELETE` | `/api/v1/agents/tokens/{credential_id}` | Revoke a credential by opaque record ID (administrator session and CSRF required) |

---

## ⚡ Quick Start & Deployment

### 1. Prerequisites

- **Python 3.11+**
- **Node.js 18+** (for frontend dashboard)
- **Docker & Docker Compose** (for Kafka, ClickHouse, Redis)

### 2. Start Infrastructure

Run the core storage and message bus services:

```powershell
# Apache Kafka & Zookeeper
docker compose -f infra/kafka/docker-compose.yaml up -d

# ClickHouse Analytics Database
docker compose -f infra/clickhouse/docker-compose.yaml up -d

# Redis Cache & Rate Limiter
docker compose -f infra/redis/docker-compose.yaml up -d
```

### 3. Setup Python Virtual Environment

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 4. Launch Backend, Worker & Dashboard

```powershell
# Terminal 1: Backend API Gateway
python -m backend

# Terminal 2: Detection Worker
python -m worker.main

# Terminal 3: Frontend Dashboard
cd dashboard
npm install
npm run dev
```

### 5. Deploy & Run Agent on Endpoints

In the dashboard, sign in as an administrator and create a bootstrap token under
**Settings → Agent Credentials & Enrollment Tokens**. The token is shown only once,
expires after 30 minutes, and can enroll only one agent. Do not log or share it.
Enroll a local development agent over loopback HTTP, or use verified HTTPS for a
remote endpoint:

```powershell
# Enroll once; enrollment saves the permanent token and backend-assigned identity
# in agent/.env. The tenant argument is not needed or trusted by the backend.
python -m agent.enroll --token "<BOOTSTRAP_TOKEN>" --backend "http://localhost:8000"

# For a remote endpoint, use the backend's verified HTTPS endpoint instead:
python -m agent.enroll --token "<BOOTSTRAP_TOKEN>" --backend "https://<BACKEND_HOST>:8000"

# Option A: run in the foreground
python -m agent.main

# Option B instead: install and start at boot (Linux systemd / Windows Task Scheduler)
python -m agent.service install
python -m agent.service start

# Check service status
python -m agent.service status
```

---

## 🧪 Running Automated Tests

Run the unified test runner to execute all test suites across the entire platform:

```powershell
python run_tests.py
```

Or run individual component test suites:

```powershell
# Agent Tests (Buffer, Envelopes, Assembler, Service, Enrollment)
python -m pytest agent/tests -v

# Backend Tests (REST API, Ingestion, Enrollment, Health)
python -m pytest backend/tests -v

# Worker Tests (Detection Engine, Sliding Windows, Rules)
python -m pytest worker/tests -v
```

---

## ⚙️ Configuration Reference

### `agent/.env`

| Variable                   | Default                                  | Description                                            |
| -------------------------- | ---------------------------------------- | ------------------------------------------------------ |
| `SIEM_BACKEND_URL`         | `http://127.0.0.1:8000/api/v1/telemetry` | Backend ingestion endpoint URL                         |
| `SIEM_AGENT_TOKEN`         | `""`                                     | Provisioned agent token for authenticated ingestion    |
| `SIEM_AGENT_ID`            | `""`                                     | Backend-assigned agent identity saved during enrollment |
| `SIEM_TENANT_ID`           | `default`                                | Backend-assigned tenant identity saved during enrollment |
| `SIEM_COLLECTION_INTERVAL` | `5`                                      | Polling and collection interval in seconds             |
| `SIEM_BUFFER_DB_PATH`      | `.agent_buffer.db`                       | Local SQLite database file for offline buffering       |
| `SIEM_BUFFER_MAX_EVENTS`   | `25000`                                  | Maximum number of pending events held in buffer        |
| `SIEM_BUFFER_MAX_BYTES`    | `52428800` (50MB)                        | Maximum serialized pending-event payload bytes         |
| `SIEM_BUFFER_RETENTION_SECONDS` | `604800` (7 days)                   | Maximum age for unacknowledged events before explicit expiry |

### `backend/.env`

| Variable                  | Default                  | Description                                          |
| ------------------------- | ------------------------ | ---------------------------------------------------- |
| `PORT`                    | `8000`                   | Backend API listen port                              |
| `ENVIRONMENT`             | `development`            | Set to `production` for deployed environments       |
| `AUTH_DB_PATH`            | `../data/sysmon_auth.db` | Protected SQLite database for administrator and agent identity/credential metadata |
| `AUTH_SESSION_COOKIE_SECURE` | derived from `ENVIRONMENT` | Must be `true` in production                         |
| `TLS_CERT_FILE`           | unset                    | Organization-provided certificate for direct HTTPS |
| `TLS_KEY_FILE`            | unset                    | Matching private key; configure both TLS variables  |
| `TLS_TERMINATED`           | `false`                  | Set `true` only when a trusted reverse proxy terminates HTTPS |
| `DEFAULT_TENANT_ID`        | `default`                | Server-assigned tenant for new agent enrollments    |
| `ALLOWED_ORIGINS`         | `*`                      | Comma-separated dashboard origins; set explicitly in production |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092`        | Kafka broker address                                 |
| `KAFKA_TOPIC`             | `telemetry_data`         | Telemetry event topic                                |
| `REDIS_URL`               | `redis://localhost:6379` | Redis connection URL for rate limiting and other cache services |
| `CLICKHOUSE_HOST`         | `localhost`              | ClickHouse server host                               |
| `CLICKHOUSE_PORT`         | `8123`                   | ClickHouse HTTP interface port                       |
| `CLICKHOUSE_USERNAME`     | `backend`                | ClickHouse user account                              |
| `CLICKHOUSE_PASSWORD`     | `***`                    | ClickHouse password                                  |
| `CLICKHOUSE_DB`           | `metrics`                | ClickHouse database name                             |
| `REQUIRE_AGENT_AUTH`      | `true`                   | Agent authentication is mandatory and cannot be disabled |

### Administrator security

The backend creates `data/sysmon_auth.db` on first use and enables SQLite WAL mode.
The first administrator is created through **Initial administrator setup** in the
dashboard, but the setup request is accepted only from a loopback client. It is
available once; there are no default credentials or public registration links.
Administrator passwords use Argon2id. Only hashes of administrator session,
CSRF, bootstrap, and permanent agent tokens are persisted; plaintext credentials
are returned only at issuance, enrollment, or the authenticated renewal response.
Agent identities and credential metadata
(including bootstrap tokens, expirations, revocation, and rotation overlap) are
stored in the protected SQLite database; bootstrap tokens expire after 30 minutes
and are single-use. The dashboard can view credential metadata but cannot retrieve
an issued credential again. Agent IDs and tenant IDs are assigned by the backend;
the enrollment tenant field is ignored, and telemetry identity fields must match
the authenticated credential. Session cookies are `HttpOnly`, `SameSite=Strict`,
and `Secure` in production. State-changing dashboard requests require a CSRF token.

For production, set `ENVIRONMENT=production`, `ALLOWED_ORIGINS` to the dashboard's
exact origin, and `AUTH_SESSION_COOKIE_SECURE=true`. Terminate HTTPS with your
organization's certificate either directly using `TLS_CERT_FILE` and `TLS_KEY_FILE`,
or at a trusted reverse proxy; do not expose the backend over plaintext HTTP.
Production startup requires direct TLS certificate files or `TLS_TERMINATED=true`.
Agent enrollment, telemetry, and renewal clients use verified HTTPS; plaintext HTTP
is permitted only for loopback development. Rotated credentials overlap for a
bounded recovery interval so an agent can retry after a lost renewal response.
Revoking an agent credential disables that agent's current and overlapping
credentials without deleting historical telemetry. Re-enrollment issues a new
backend-generated agent identity.
Set the dashboard's `VITE_API_URL` to the backend's HTTPS origin as well.
Bind the local setup interface so that remote clients cannot reach it through a
loopback-terminating proxy. The auth database is excluded from version control and
should be owned/readable only by the Sysmon service account.

Telemetry acknowledgement means that Kafka has returned a successful record
delivery result (producer `acks=all`) and the backend has persisted the event IDs
in its receipt ledger. If Kafka is unavailable or rejects a record, the endpoint
returns a retryable error and does not acknowledge the batch. The agent retains
unacknowledged events until a valid acknowledgement or its configured local
retention/overflow policy explicitly expires or evicts them. Configure Kafka
replication and `min.insync.replicas` to match the deployment's durability
requirements; the broker's successful acknowledgement is the durability boundary.

To recover an administrator account from the host operating system, run
`python -m backend.auth_recovery` as the Sysmon service account. This sets a new
password and revokes all current sessions; it does not retrieve the old password.

### `worker/.env`

| Variable                  | Default           | Description                                 |
| ------------------------- | ----------------- | ------------------------------------------- |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092` | Kafka broker address                        |
| `KAFKA_TOPIC`             | `telemetry_data`  | Kafka topic to consume                      |
| `MAX_BATCH_SIZE`          | `1000`            | Dual-trigger batch record threshold         |
| `MAX_WAIT_TIME`           | `5.0`             | Dual-trigger batch flush timeout in seconds |
| `CLICKHOUSE_HOST`         | `localhost`       | ClickHouse server host                      |
| `CLICKHOUSE_PORT`         | `8123`            | ClickHouse HTTP interface port              |
| `SLACK_WEBHOOK_URL`       | `""`              | Incoming Slack webhook URL for alerts       |
| `DISCORD_WEBHOOK_URL`     | `""`              | Incoming Discord webhook URL for alerts     |
| `SMTP_HOST`               | `""`              | Outgoing SMTP server address                |

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
