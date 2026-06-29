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


settings = Config()
