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
            with open(ENV_FILE_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, val = line.split('=', 1)
                        os.environ[key.strip()] = val.strip()

        # 2. Map environment variables to strongly-typed class attributes
        # (Using fallbacks/defaults in case the variable isn't set)
        self.BACKEND_URL = os.getenv("SIEM_BACKEND_URL", "http://127.0.0.1:8000/api/v1/telemetry")
        self.COLLECTION_INTERVAL = int(os.getenv("SIEM_COLLECTION_INTERVAL", 10))
        self.LOG_LEVEL = os.getenv("SIEM_LOG_LEVEL", "INFO")

settings = Config()