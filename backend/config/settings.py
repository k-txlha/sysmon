import os
import logging
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
                        os.environ.setdefault(key.strip(), val.strip())
        self.PORT = int(os.getenv("PORT", 8000))
        self.ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
        self.AUTH_DB_PATH = Path(
            os.getenv(
                "AUTH_DB_PATH",
                str(BASE_DIR.parent / "data" / "sysmon_auth.db"),
            )
        ).expanduser()
        self.AUTH_SESSION_COOKIE_SECURE = (
            os.getenv("AUTH_SESSION_COOKIE_SECURE", "").lower() in ("true", "1", "yes")
            if os.getenv("AUTH_SESSION_COOKIE_SECURE") is not None
            else self.ENVIRONMENT == "production"
        )
        self.TLS_CERT_FILE = os.getenv("TLS_CERT_FILE")
        self.TLS_KEY_FILE = os.getenv("TLS_KEY_FILE")
        if bool(self.TLS_CERT_FILE) != bool(self.TLS_KEY_FILE):
            raise ValueError("TLS_CERT_FILE and TLS_KEY_FILE must be configured together.")
        if self.ENVIRONMENT == "production" and not self.AUTH_SESSION_COOKIE_SECURE:
            raise ValueError("Production deployments must enable secure administrator cookies.")
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
        configured_agent_auth = os.getenv("REQUIRE_AGENT_AUTH", "true").lower()
        if configured_agent_auth in ("false", "0", "no"):
            logging.getLogger(__name__).warning(
                "REQUIRE_AGENT_AUTH=false is ignored; agent authentication is mandatory."
            )
        self.REQUIRE_AGENT_AUTH = True
        self.AGENT_TOKEN_HEADER = os.getenv("AGENT_TOKEN_HEADER", "X-Agent-Token")

        # CORS
        allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
        self.ALLOWED_ORIGINS = [
            origin.strip() for origin in allowed_origins_raw.split(",") if origin.strip()
        ]
        if self.ENVIRONMENT == "production" and self.ALLOWED_ORIGINS == ["*"]:
            raise ValueError("Production deployments must configure explicit ALLOWED_ORIGINS.")

        # Detection Rules Directory
        # Default to worker/detection/rules relative to repo root
        repo_root = BASE_DIR.parent
        self.RULES_DIR = repo_root / "worker" / "detection" / "rules"


settings = BackendSettings()
