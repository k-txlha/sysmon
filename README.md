# 🚀 Real-Time SIEM Telemetry Ingestion

Lightweight, modular pipeline for collecting endpoint telemetry, streaming via Kafka, and ingesting into ClickHouse for analytics.

## 📋 Overview

This repository contains three primary components:

- `agent/` — endpoint collectors for system metrics, processes, platform details and network state.
- `backend/` — FastAPI ingestion gateway that accepts agent payloads and forwards them to Kafka.
- `worker/` — asynchronous consumers that batch Kafka messages and write to ClickHouse.

The repo also includes Docker Compose files for local Kafka and ClickHouse under `kafka/` and `clickhouse/`.

**High-level data flow**

```
agent -> backend (FastAPI) -> Kafka -> worker -> ClickHouse
```

## 📁 Repository Layout

```
├── agent/
│   ├── collectors/
│   │   ├── network_collector.py
│   │   ├── platform_collector.py
│   │   ├── process_collector.py
│   │   └── system_collector.py
│   ├── utils/
│   │   ├── assembler.py
│   │   ├── config.py
│   │   ├── logger.py
│   │   └── transport.py
│   └── main.py
│
├── backend/
│   ├── api/
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── transport.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py
│   ├── services/
│   │   ├── __init__.py
│   │   └── producer.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── logger.py
│   └── main.py
│
├── worker/
│   ├── db/
│   │   └── ch_client.py
│   ├── utils/
│   │   ├── config.py
│   │   └── logger.py
│   └── main.py
│
├── clickhouse/
│   ├── docker-compose.yaml
│   └── users.xml
│
├── kafka/
│   └── docker-compose.yaml
│
```

## ⚙️ Dependencies / `requirements.txt`

This repository uses a single `requirements.txt` at the repository root. Install all Python dependencies with:

```powershell
pip install -r requirements.txt
```

If you prefer per-service dependency files, place `requirements.txt` under `agent/`, `backend/`, and `worker/` and install those individually.

## 🛠️ Requirements

- Python 3.11+ (recommended)
- Docker & Docker Compose (for local Kafka and ClickHouse)

## ⚡ Quick Start (local development)

1. Start infrastructure (Kafka + ClickHouse)

```powershell
docker compose -f kafka/docker-compose.yaml up -d
docker compose -f clickhouse/docker-compose.yaml up -d
```

2. Configure environment files

Each module contains its own `.env` file. Edit the following files as needed before running services:

- `agent/.env` — agent-specific settings (server URL, interval)
- `backend/.env` — ingestion gateway settings (Kafka brokers, topic names)
- `worker/.env` — consumer settings (Kafka brokers, ClickHouse connection)

3. Create and activate a Python virtual environment (example)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

4. Run services (each in its own terminal)

```powershell
# Start the backend API (or run with uvicorn if app object is exposed)
python backend\main.py

# Start the worker
python worker\main.py

# Start a local agent instance
python agent\main.py
```

Windows agent note (required for collecting certain telemetry):

On Windows the agent requires elevated privileges to access system metrics and Windows Event Logs. Start PowerShell with Administrator rights before running the agent:

1. Search for PowerShell, right-click and choose "Run as administrator".
2. (Optional) Activate the repo virtualenv if you created one:

```powershell
.\.venv\Scripts\Activate.ps1
```

3. Run the agent from the elevated PowerShell session:

```powershell
python agent\main.py
```

Notes:

- If dependencies are split per-service, activate the appropriate virtualenv and install that service's `requirements.txt`.
- The `backend` may expose a FastAPI ASGI `app` — use `uvicorn backend.main:app --reload` when developing.

## 🔧 Configuration and Conventions

- Kafka producers use idempotent configs (`acks=all`, `enable_idempotence=True`) to avoid duplicates.
- Workers batch records before writing to ClickHouse to optimize insert throughput (bulk flush by size or time).
- ClickHouse schema and migration utilities live under `worker/db/`.

## 🔍 Troubleshooting

- Check Docker container logs for Kafka/ClickHouse: `docker compose kafka/docker-compose.yaml logs -f`.
- If the backend fails to connect to Kafka, verify `backend/.env` broker addresses and that containers are reachable.
- For ClickHouse insert errors, review the schema in `worker/db` and ensure the ClickHouse server is reachable and accepts connections.

## 🤝 Contributing

Please open issues or pull requests. Describe the environment, steps to reproduce, and include logs when relevant.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
