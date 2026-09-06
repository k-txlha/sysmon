import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"


# load .env and replace the vars
class BackendSettings:
    def __init__(self) -> None:
        if ENV_PATH.exists():
            with open(ENV_PATH) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip()
        self.PORT = int(os.getenv("PORT", 8000))
        self.KAFKA_BOOTSTRAP_SERVERS = os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"
        )
        self.KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "telemetry_data")
        self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

        # ClickHouse Configuration
        self.CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
        self.CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", 8123))
        self.CLICKHOUSE_USERNAME = os.getenv("CLICKHOUSE_USERNAME", "backend")
        self.CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "W3lc0m3_2026!")
        self.CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "metrics")

        # Agent Authentication & Security
        self.REQUIRE_AGENT_AUTH = (
            os.getenv("REQUIRE_AGENT_AUTH", "false").lower() in ("true", "1", "yes")
        )
        self.AGENT_TOKEN_HEADER = os.getenv("AGENT_TOKEN_HEADER", "X-Agent-Token")

        # CORS
        allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
        self.ALLOWED_ORIGINS = [
            origin.strip() for origin in allowed_origins_raw.split(",") if origin.strip()
        ]

        # Detection Rules Directory
        # Default to worker/detection/rules relative to repo root
        repo_root = BASE_DIR.parent
        self.RULES_DIR = repo_root / "worker" / "detection" / "rules"


settings = BackendSettings()

