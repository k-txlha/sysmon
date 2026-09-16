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
                                       │ Produce EventEnvelopes
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
└────────────┬────────────┘                              └────────────▲────────────┘
             │                                                        │
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
│   ├── tests/                     # Agent test suite (buffer, envelope, assembler)
│   ├── .env                       # Agent configuration
│   └── main.py                    # Agent execution daemon & collection loop
│
├── backend/                       # REST API & Telemetry Ingestion Gateway
│   ├── api/v1/                    # Versioned REST endpoints
│   │   ├── agents.py              # Agent enrollment tokens & health status
│   │   ├── alerts.py              # Alert query, stats & status management
│   │   ├── devices.py             # Host inventory & hardware/OS analytics
│   │   ├── events.py              # Security audit log & raw event queries
│   │   ├── health.py              # System health & dependency status
│   │   ├── rules.py               # Detection rule CRUD & YAML validation
│   │   └── transport.py           # Strict EventEnvelope ingestion endpoint
│   ├── config/                    # Backend configuration
│   │   └── settings.py            # Environment settings & ClickHouse/Kafka/Redis config
│   ├── models/                    # Ingestion data models & batch schemas
│   │   └── envelope.py            # Backend EventEnvelope & IngestionBatchRequest models
│   ├── services/                  # Business logic & query services
│   │   ├── agent_service.py       # Agent token authentication & heartbeat tracking
│   │   ├── ch_service.py          # ClickHouse analytical query engine
│   │   └── producer.py            # Asynchronous Kafka producer service
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
  "observed_at": "2026-09-16T14:30:00.000000Z",
  "received_at": "2026-09-16T14:30:00.085000Z",
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

### 2. 🛡️ Agent Resilience & Offline Disk Buffering (Phase 1)
- **Local Bounded Disk Buffer (`agent/utils/buffer.py`)**: Events are staged in an SQLite WAL-mode FIFO queue. If the backend is unreachable or rate-limits with 429, events remain safely stored on disk and drain automatically upon reconnection.
- **Agent Health Telemetry (`agent.health`)**: Automatically captures and transmits agent process memory (RSS MB), process CPU usage, local queue depth, and dropped event counters.
- **Zero Event Loss**: Monotonic sequence numbering per session and disk quota enforcement.

### 3. ⚡ Ingestion Gateway & Security Analytics API (`backend/`)
- **Strict Ingestion**: Validates all incoming payloads against `EventEnvelope` and `IngestionBatchRequest` schemas; rejects malformed inputs with `HTTP 422`.
- **Server-Side Timestamping**: Adds `received_at` UTC timestamps and records live heartbeats in Redis.
- **Analytical Query Engine**: `ClickHouseQueryService` provides aggregated KPI statistics, device history, paginated event searches, and threat analytics.
- **Token Management**: Per-agent enrollment tokens with rotation and revocation.

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

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status (Kafka, ClickHouse, Redis) |
| `POST` | `/api/v1/telemetry` | Ingest standardized EventEnvelope telemetry (Rate-limited & authenticated) |
| `GET` | `/api/v1/alerts` | Paginated alert list with severity, agent, rule, and status filters |
| `GET` | `/api/v1/alerts/stats` | Aggregated alert breakdown and 24-hour timeline statistics |
| `PATCH` | `/api/v1/alerts/{alert_id}/status` | Update alert resolution status (`0` = Open, `1` = Resolved) |
| `GET` | `/api/v1/devices` | Query device inventory, operating system details, and online status |
| `GET` | `/api/v1/devices/stats` | Aggregated device metrics (active hosts, OS distribution) |
| `GET` | `/api/v1/devices/{agent_id}` | Detailed hardware, network, and telemetry for a specific device |
| `GET` | `/api/v1/devices/{agent_id}/history` | Historical telemetry snapshots for an agent |
| `GET` | `/api/v1/events` | Query raw security authentication logs with filters and pagination |
| `GET` | `/api/v1/rules` | List all active detection rules |
| `POST` | `/api/v1/rules/{rule_name}/toggle` | Enable or disable a detection rule |
| `GET` | `/api/v1/agents/tokens` | List registered agent enrollment tokens |
| `POST` | `/api/v1/agents/token` | Generate a new secure agent enrollment token |
| `DELETE` | `/api/v1/agents/tokens/{token}` | Revoke an existing agent enrollment token |

---

## ⚡ Quick Start

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

### 4. Launch Services

Open separate terminal windows for each component:

```powershell
# Terminal 1: Backend API Gateway
python backend\main.py

# Terminal 2: Detection Worker
python worker\main.py

# Terminal 3: Telemetry Agent
python agent\main.py

# Terminal 4: Frontend Dashboard (Optional)
cd dashboard
npm install
npm run dev
```

---

## 🧪 Running Automated Tests

Run the unified test runner to execute all test suites across the entire platform:

```powershell
python run_tests.py
```

Or run individual component test suites:

```powershell
# Agent Tests (Buffer, Envelopes, Assembler)
python -m pytest agent/tests -o pythonpath=agent -v

# Backend Tests (REST API, Envelope Ingestion, Tokens)
python -m pytest backend/tests -o pythonpath=backend -v

# Worker Tests (Detection Engine, Sliding Windows, Rule Fixtures)
python -m pytest worker/tests -o pythonpath=worker -v
```

---

## ⚙️ Configuration Reference

### `agent/.env`
| Variable | Default | Description |
|---|---|---|
| `SIEM_BACKEND_URL` | `http://127.0.0.1:8000/api/v1/telemetry` | Backend ingestion endpoint URL |
| `SIEM_AGENT_TOKEN` | `""` | Optional enrollment token for authenticated ingestion |
| `SIEM_COLLECTION_INTERVAL`| `5` | Polling and collection interval in seconds |
| `SIEM_BUFFER_DB_PATH` | `.agent_buffer.db` | Local SQLite database file for offline buffering |
| `SIEM_BUFFER_MAX_EVENTS` | `25000` | Maximum number of pending events held in buffer |
| `SIEM_BUFFER_MAX_BYTES` | `52428800` (50MB) | Disk quota limit for local buffer before FIFO eviction |

### `backend/.env`
| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | Backend API listen port |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092` | Kafka broker address |
| `KAFKA_TOPIC` | `telemetry_data` | Telemetry event topic |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL for rate limiting & token store |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse server host |
| `CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP interface port |
| `CLICKHOUSE_USERNAME` | `backend` | ClickHouse user account |
| `CLICKHOUSE_PASSWORD` | `***` | ClickHouse password |
| `CLICKHOUSE_DB` | `metrics` | ClickHouse database name |
| `REQUIRE_AGENT_AUTH` | `false` | Enable/disable mandatory agent token authentication |

### `worker/.env`
| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092` | Kafka broker address |
| `KAFKA_TOPIC` | `telemetry_data` | Kafka topic to consume |
| `MAX_BATCH_SIZE` | `1000` | Dual-trigger batch record threshold |
| `MAX_WAIT_TIME` | `5.0` | Dual-trigger batch flush timeout in seconds |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse server host |
| `CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP interface port |
| `SLACK_WEBHOOK_URL` | `""` | Incoming Slack webhook URL for alerts |
| `DISCORD_WEBHOOK_URL` | `""` | Incoming Discord webhook URL for alerts |
| `SMTP_HOST` | `""` | Outgoing SMTP server address |

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
