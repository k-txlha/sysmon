import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"


class Config:
    def __init__(self):
        if ENV_FILE_PATH.exists():
            with open(ENV_FILE_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip()

        self.CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
        self.CLICKHOUSE_PORT = os.getenv("CLICKHOUSE_PORT", 8443)
        self.CLICKHOUSE_USERNAME = os.getenv("CLICKHOUSE_USERNAME", None)
        self.CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", None)
        self.CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "metrics")
        self.KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "telemetry_data")
        self.KAFKA_BOOTSTRAP_SERVERS = os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"
        )
        self.MAX_BATCH_SIZE = os.getenv("MAX_BATCH_SIZE", 1000)
        self.MAX_WAIT_TIME = os.getenv("MAX_WAIT_TIME", 5.0)

        # ── Alerting channel configuration ─────────────────────────────
        # Set any of these to enable that channel; leave blank to disable.
        self.SLACK_WEBHOOK_URL    = os.getenv("SLACK_WEBHOOK_URL", "")
        self.DISCORD_WEBHOOK_URL  = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.SYSMON_DASHBOARD_URL = os.getenv("SYSMON_DASHBOARD_URL", "")

        # Email / SMTP (works with Gmail, SendGrid, SES, Postfix, etc.)
        self.SMTP_HOST     = os.getenv("SMTP_HOST", "")
        self.SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
        self.SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
        self.SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
        self.SMTP_FROM     = os.getenv("SMTP_FROM", "")
        # Comma-separated list: "security@co.com,cto@co.com"
        self.SMTP_TO       = os.getenv("SMTP_TO", "")


settings = Config()
