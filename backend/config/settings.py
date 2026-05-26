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
                        if line and not line.startswith('#'):
                            key, val = line.split('=', 1)
                            os.environ[key.strip()] = val.strip()
        self.PORT = int(os.getenv("PORT", 8000))
        self.KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
        self.KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_TELEMETRY", "telemetry_data")

settings = BackendSettings()
