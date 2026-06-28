import json
import time
from utils.logger import setup_logger
from utils.assembler import assemble_telemetry_payload
from utils.transport import ship_to_backend
from utils.config import settings

logger = setup_logger("main")


def main():
    logger.info("Initializing SIEM Agent...")
    # Read the interval from settings
    logger.info(
        f"Agent loop scheduled to run every {settings.COLLECTION_INTERVAL} seconds."
    )
    print("-" * 60)

    try:
        while True:
            payload = assemble_telemetry_payload()
            ship_to_backend(payload)

            # Use configuration value for sleep timer
            time.sleep(settings.COLLECTION_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Agent gracefully stopped by user interaction.")


if __name__ == "__main__":
    main()
