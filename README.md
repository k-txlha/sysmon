# 🛡️ Sysmon — Open-Source SIEM & Security Telemetry Platform

A high-performance, modular, and cloud-ready **Security Information and Event Management (SIEM)** platform. Sysmon collects cross-platform endpoint telemetry, streams events through Apache Kafka, performs high-throughput batching and analytical persistence in ClickHouse, executes real-time threat detection with custom YAML rules, dispatches multi-channel alerts (Slack, Discord, Email), and exposes a comprehensive FastAPI REST API for security operations dashboards.

---

## 📋 Architecture & Data Flow

```
                                  ┌────────────────────────┐
                                  │      Sysmon Agent      │
                                  │  (Endpoint Telemetry)  │
                                  └───────────┬────────────┘
                                              │ POST /api/v1/transport
                                              │ (Auth + Redis Rate Limiter)
                                              ▼
                                  ┌────────────────────────┐
                                  │    Backend Gateway     │
                                  │       (FastAPI)        │
                                  └───────────┬────────────┘
                                              │ Produce Events
                                              ▼
                                  ┌────────────────────────┐
                                  │      Apache Kafka      │
                                  │    (telemetry_data)    │
                                  └───────────┬────────────┘
                                              │ Consume Streams
                                              ▼
                                  ┌────────────────────────┐
                                  │     Worker Service     │
                                  │ (Dual-Trigger Batcher) │
                                  └─────┬──────────────┬───┘
                                        │              │
                   ┌────────────────────┘              └────────────────────┐
                   ▼                                                        ▼
      ┌─────────────────────────┐                              ┌─────────────────────────┐
      │    Detection Engine     │                              │   ClickHouse Database   │
      │  (YAML Rule Evaluator)  │                              │ (DEVICES, EVENTS, etc.) │
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
                                                               │  (Next.js / Vite / UI)  │
                                                              └─────────────────────────┘
```

---

## 📁 Repository Layout

```
├── agent/                         # Endpoint Telemetry Collector
│   ├── collectors/                # Specialized metric & audit collectors
│   │   ├── network_collector.py   # Network interfaces, IPs, hostnames, sockets
│   │   ├── platform_collector.py  # OS details, release, architecture, login audits
│   │   ├── process_collector.py   # Process trees, PIDs, CPU & memory per process
│   │   └── system_collector.py    # CPU usage, memory stats, disk utilization
│   ├── utils/                     # Transport, configuration, and logging
│   │   ├── assembler.py           # Aggregates sub-collector metrics into payload
│   │   ├── config.py              # Environment configuration loader
│   │   ├── logger.py              # Structured logging utility
│   │   └── transport.py           # HTTP client with retry logic (429 handling)
│   ├── .env                       # Agent configuration
│   └── main.py                    # Agent execution daemon
│
├── backend/                       # REST API & Telemetry Gateway
│   ├── api/v1/                    # Versioned REST endpoints
│   │   ├── agents.py              # Agent registration, token auth & heartbeat
│   │   ├── alerts.py              # Alert query, filtering & status management
│   │   ├── devices.py             # Host inventory & hardware/OS analytics
│   │   ├── events.py              # Security audit log & raw telemetry queries
│   │   ├── health.py              # System health & dependency status
│   │   ├── rules.py               # Detection rule CRUD & YAML validation
│   │   └── transport.py           # Telemetry ingestion endpoint with rate limiting
│   ├── config/                    # Backend configuration
│   │   └── settings.py            # Environment settings & ClickHouse/Kafka/Redis config
│   ├── services/                  # Business logic & query services
│   │   ├── agent_service.py       # Agent state tracking & heartbeat monitor
│   │   ├── ch_service.py          # ClickHouse analytical query engine
│   │   └── producer.py            # Asynchronous Kafka producer service
│   ├── tests/                     # Backend test suite
│   │   └── test_api.py            # API endpoint integration & unit tests
│   ├── utils/                     # Helper modules
│   │   ├── logger.py              # Backend structured logger
│   │   └── rate_limiter.py        # Redis sliding-window & token-bucket rate limiter
│   ├── .env                       # Backend environment configuration
│   └── main.py                    # FastAPI application entrypoint & ASGI server
│
├── worker/                        # Stream Processing, Detection & Alerting Worker
│   ├── alerting/                  # Modular notification framework
│   │   ├── discord.py             # Discord webhook integration with rich embeds
│   │   ├── dispatcher.py          # Fan-out dispatcher to active channels + ClickHouse
│   │   ├── email.py               # SMTP email dispatcher with HTML/plain-text templates
│   │   └── slack.py               # Slack webhook integration with Block Kit formatting
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
│   ├── tests/                     # Worker test suite
│   │   └── test_engine.py         # Detection engine & rule execution tests
│   ├── utils/                     # Worker utilities
│   │   ├── config.py              # Worker settings, batch thresholds & webhook URLs
│   │   └── logger.py              # Worker structured logger
│   ├── .env                       # Worker environment configuration
│   └── main.py                    # Kafka consumer, dual-trigger batcher & detection loop
│
├── infra/                         # Infrastructure Compose Files
│   ├── clickhouse/                # ClickHouse server configuration & compose
│   │   ├── docker-compose.yaml
│   │   ├── users.xml
│   │   └── .env
│   ├── kafka/                     # Apache Kafka & Zookeeper compose
│   │   └── docker-compose.yaml
│   └── redis/                     # Redis cache & rate limiter compose
│       └── docker-compose.yaml
│
├── requirements.txt               # Unified project dependencies
└── README.md                      # Project documentation
```

---

## ✨ Key Features

### 1. 🔍 Endpoint Telemetry Collection (`agent/`)
- Cross-platform collection of system metrics (CPU, RAM, disk, network interfaces, open sockets).
- Process inventory and process tree tracing.
- Windows Security Event Log parsing (Logon/Logoff audits, Event IDs 4624, 4625, etc.).
- Exponential backoff and retry handling on HTTP 429 rate limit responses.

### 2. ⚡ Ingestion Gateway & Security Analytics API (`backend/`)
- **High-throughput Ingestion**: Validates and routes agent payloads into Kafka topics asynchronously.
- **Rate Limiting**: Distributed token-bucket / sliding-window rate limiting backed by Redis.
- **Analytical Query Engine**: `ClickHouseQueryService` provides aggregated metrics, host summaries, paginated event searches, and alert analytics.
- **Rule Management**: Full CRUD API for managing detection rules dynamically with YAML validation.
- **Agent Lifecycle**: Agent enrollment tokens, registration, and heartbeat tracking.

### 3. 🧠 Real-Time Detection Engine (`worker/detection/`)
- Declarative YAML rule syntax with multi-condition logic (`equals`, `contains`, `regex`, `gt`, `lt`, `in`, `not_in`).
- Stateful time-window aggregations (e.g. 5 failed logons within 60 seconds).
- Built-in detection scenarios:
  - **Brute Force Attacks**: Excessive failed login attempts within a sliding time window.
  - **After-Hours Logins**: Authentication outside authorized operating hours.
  - **Privileged Account Logins**: Root / Administrator logins from non-whitelisted sources.
  - **Multiple IP Logins**: Same identity authenticating across disparate IP addresses concurrently.
  - **New Device Seen**: First-time host / agent appearances.
  - **Off-Hours Service Execution**: Suspicious service launches during off-peak windows.
  - **Logon Type Anomalies**: Rapid switching between interactive and network logon types.

### 4. 📢 Multi-Channel Alerting Framework (`worker/alerting/`)
- **Slack**: Rich Block Kit message cards with severity badges, host details, and timestamp tags.
- **Discord**: Color-coded embedded alerts formatted for security operations channels.
- **Email (SMTP)**: Multi-recipient HTML and plain-text security incident reports.
- **ClickHouse Storage**: Automatic persistence of all triggered alerts to the `ALERTS` analytics table.

---

## 🌐 REST API Reference (`/api/v1`)

The backend exposes an interactive OpenAPI documentation at `http://localhost:8000/docs`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service health status (Kafka, ClickHouse, Redis) |
| `POST` | `/api/v1/transport` | Ingest agent telemetry payload (Rate-limited) |
| `GET` | `/api/v1/alerts` | List alerts with severity, rule ID, and time range filtering |
| `GET` | `/api/v1/alerts/summary` | Aggregated alert breakdown by severity and status |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve specific alert details |
| `PATCH` | `/api/v1/alerts/{alert_id}/status` | Update alert status (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) |
| `GET` | `/api/v1/devices` | Query device inventory and online status |
| `GET` | `/api/v1/devices/summary` | Aggregated device metrics (OS breakdown, active hosts) |
| `GET` | `/api/v1/devices/{agent_id}` | Detailed hardware, network, and telemetry for a specific device |
| `GET` | `/api/v1/events` | Query raw security events and audit records with pagination |
| `GET` | `/api/v1/events/types` | List unique security event IDs and action types |
| `GET` | `/api/v1/rules` | List all active detection rules |
| `GET` | `/api/v1/rules/{rule_id}` | Fetch detection rule definition |
| `POST` | `/api/v1/rules` | Create and deploy a new YAML detection rule |
| `PUT` | `/api/v1/rules/{rule_id}` | Update an existing detection rule |
| `DELETE` | `/api/v1/rules/{rule_id}` | Delete a detection rule |
| `POST` | `/api/v1/rules/validate` | Validate detection rule YAML syntax and condition tree |
| `GET` | `/api/v1/agents` | List registered agents and health status |
| `POST` | `/api/v1/agents/register` | Register a new endpoint agent |
| `POST` | `/api/v1/agents/{agent_id}/heartbeat` | Record agent heartbeat |
| `GET` | `/api/v1/agents/{agent_id}` | Get agent metadata and connection info |

---

## ⚡ Quick Start

### 1. Prerequisites
- **Python 3.11+**
- **Docker & Docker Compose**

### 2. Start Infrastructure
Run the core services (Kafka, ClickHouse, Redis) using Docker Compose:

```powershell
# Start Apache Kafka & Zookeeper
docker compose -f infra/kafka/docker-compose.yaml up -d

# Start ClickHouse Analytics Database
docker compose -f infra/clickhouse/docker-compose.yaml up -d

# Start Redis Cache & Rate Limiter
docker compose -f infra/redis/docker-compose.yaml up -d
```

### 3. Setup Virtual Environment
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install all dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy and customize the `.env` configuration files for each component:

- `backend/.env` — Backend gateway port, Kafka broker, Redis URL, ClickHouse credentials.
- `worker/.env` — Kafka consumer settings, ClickHouse connection, alerting webhooks (Slack/Discord/SMTP).
- `agent/.env` — Backend URL, collection interval, and agent auth token.

### 5. Launch Application Services

Open separate terminals for each service:

```powershell
# Terminal 1: Start Backend API Gateway
python backend\main.py
# (Or with Uvicorn: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload)

# Terminal 2: Start Stream Processing & Detection Worker
python worker\main.py

# Terminal 3: Start Telemetry Agent (Run as Administrator on Windows for event logs)
python agent\main.py
```

---

## 🧪 Running Test Suites

The project includes comprehensive test suites covering both the REST API layer and the Threat Detection Engine:

```powershell
# Run Backend API tests
$env:PYTHONPATH="backend"; pytest backend/tests

# Run Detection Engine & Rule tests
$env:PYTHONPATH="worker"; pytest worker/tests
```

---

## 🛡️ Writing Custom Detection Rules

Detection rules are stored as YAML files under `worker/detection/rules/`. Here is an example rule detecting repeated failed logins:

```yaml
id: "RULE-001"
name: "Brute Force Login Detected"
description: "Detects multiple consecutive failed authentication attempts within a short timeframe."
severity: "HIGH"
enabled: true
event_type: "login_attempt"
window_seconds: 60
threshold: 5

conditions:
  - field: "status"
    operator: "equals"
    value: "FAILURE"

actions:
  - type: "alert"
    channels: ["slack", "discord", "email"]
```

### Supported Condition Operators:
- `equals`, `not_equals`
- `contains`, `not_contains`
- `regex`
- `in`, `not_in`
- `gt`, `gte`, `lt`, `lte`

---

## ⚙️ Configuration Reference

### `backend/.env`
| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | Backend API listen port |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092` | Kafka broker address |
| `KAFKA_TOPIC` | `telemetry_data` | Telemetry event topic |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL for rate limiting |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse server host |
| `CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP interface port |
| `CLICKHOUSE_USERNAME` | `backend` | ClickHouse user account |
| `CLICKHOUSE_PASSWORD` | `***` | ClickHouse password |
| `CLICKHOUSE_DB` | `metrics` | ClickHouse database name |
| `REQUIRE_AGENT_AUTH` | `false` | Enable/disable mandatory agent token authentication |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) |

### `worker/.env`
| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:29092` | Kafka broker address |
| `KAFKA_TOPIC` | `telemetry_data` | Kafka topic to consume |
| `MAX_BATCH_SIZE` | `1000` | Dual-trigger batch record threshold |
| `MAX_WAIT_TIME` | `5.0` | Dual-trigger batch flush timeout (seconds) |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse server host |
| `CLICKHOUSE_PORT` | `8443` | ClickHouse native/HTTP port |
| `SLACK_WEBHOOK_URL` | `""` | Incoming Slack webhook URL for alerts |
| `DISCORD_WEBHOOK_URL` | `""` | Incoming Discord webhook URL for alerts |
| `SMTP_HOST` | `""` | Outgoing SMTP server address |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS / TLS) |
| `SMTP_USERNAME` | `""` | SMTP authentication user |
| `SMTP_PASSWORD` | `""` | SMTP authentication password |
| `SMTP_FROM` | `""` | Sender email address |
| `SMTP_TO` | `""` | Comma-separated list of recipient email addresses |

---

## 🤝 Contributing

1. Fork the repository and create your feature branch: `git checkout -b feature/my-new-feature`
2. Commit your changes: `git commit -am 'Add some feature'`
3. Push to the branch: `git push origin feature/my-new-feature`
4. Submit a Pull Request.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
