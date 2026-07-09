import requests
from utils.logger import setup_logger
from utils.config import settings  # <--- Import your new config instance
import time
import random

logger = setup_logger("transport")


def ship_to_backend(payload):
    if not payload:
        return False

    initial_backoff = 2.0
    max_backoff = 30.0
    max_retries = 4

    current_backoff = initial_backoff
    retries = 0

    while retries <= max_retries:
        try:
            logger.info(f"Shipping log bundle to {settings.BACKEND_URL}...")
            response = requests.post(settings.BACKEND_URL, json=payload, timeout=5)

            if response.status_code in [200, 202]:
                logger.info("Payload successfully accepted by SIEM backend.")
                return True

            elif response.status_code == 429:
                retries += 1
                if retries > max_retries:
                    break

                jitter = random.uniform(0, 1.0)
                sleep_time = min(current_backoff + jitter, max_backoff)
                logger.warning(
                    f"Rate limited (429). Attempt {retries}/{max_retries}. "
                    f"Backing off for {sleep_time:.2f} seconds..."
                )
                time.sleep(sleep_time)
                current_backoff *= 2

            else:
                logger.error(
                    f"Backend rejected payload with status: {response.status_code}"
                )
                return False

        except requests.exceptions.RequestException as e:
            retries += 1
            if retries > max_retries:
                logger.critical(
                    f"Network error! Max retries reached. Could not connect: {e}"
                )
                return False

            logger.warning(
                f"Network issue encountered: {e}. Retrying in {current_backoff} seconds..."
            )
            time.sleep(current_backoff)
            current_backoff *= 2
    logger.error(
        "Max retries reached due to rate-limiting. Dropping log bundle to avoid blocking agent loop."
    )
    return False
