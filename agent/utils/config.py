# agent/utils/config.py
import os
from pathlib import Path

# Automatically locate the .env file relative to this file's directory
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"


class Config:
    def __init__(self):
        # 1. Load the .env file manually into os.environ if it exists
        if ENV_FILE_PATH.exists():
            with open(ENV_FILE_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip()

        # 2. Strongly-typed class attributes with safe defaults
        self.BACKEND_URL = os.getenv(
            "SIEM_BACKEND_URL", "http://127.0.0.1:8000/api/v1/telemetry"
        )
        self.AGENT_TOKEN = os.getenv("SIEM_AGENT_TOKEN", "")
        self.AGENT_ID = os.getenv("SIEM_AGENT_ID", "")
        self.TENANT_ID = os.getenv("SIEM_TENANT_ID", "default")
        self.COLLECTION_INTERVAL = int(os.getenv("SIEM_COLLECTION_INTERVAL", "5"))
        self.LOG_LEVEL = os.getenv("SIEM_LOG_LEVEL", "INFO")
        self.BUFFER_DB_PATH = os.getenv(
            "SIEM_BUFFER_DB_PATH", str(BASE_DIR / ".agent_buffer.db")
        )
        self.BUFFER_MAX_EVENTS = int(os.getenv("SIEM_BUFFER_MAX_EVENTS", "25000"))
        self.BUFFER_MAX_BYTES = int(
            os.getenv("SIEM_BUFFER_MAX_BYTES", str(50 * 1024 * 1024))
        )
        self.BUFFER_RETENTION_SECONDS = int(
            os.getenv("SIEM_BUFFER_RETENTION_SECONDS", str(7 * 24 * 60 * 60))
        )
        if self.BUFFER_MAX_EVENTS < 1:
            raise ValueError("SIEM_BUFFER_MAX_EVENTS must be greater than zero.")
        if self.BUFFER_MAX_BYTES < 1:
            raise ValueError("SIEM_BUFFER_MAX_BYTES must be greater than zero.")
        if self.BUFFER_RETENTION_SECONDS < 1:
            raise ValueError("SIEM_BUFFER_RETENTION_SECONDS must be greater than zero.")


settings = Config()
