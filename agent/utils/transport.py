import requests
from utils.logger import setup_logger
from utils.config import settings  # <--- Import your new config instance

logger = setup_logger("transport")

def ship_to_backend(payload):
    if not payload:
        return False
        
    try:
        # Use the variable from your config file directly
        logger.info(f"Shipping log bundle to {settings.BACKEND_URL}...")
        response = requests.post(settings.BACKEND_URL, json=payload, timeout=5)
        
        if response.status_code in [200, 202]:
            logger.info("Payload successfully accepted by SIEM backend.")
            return True
        else:
            logger.error(f"Backend rejected payload with status: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.critical(f"Network error! Could not connect: {e}")
        return False