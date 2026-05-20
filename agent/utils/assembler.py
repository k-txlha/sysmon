import datetime 
import socket
from utils.logger import setup_logger 

# import collectors
from collectors.system_collector import collect_system_metrics
from collectors.process_collector import collect_processes
from collectors.network_collector import collect_network_metrics
from collectors.platform_collector import collect_platform_metrics

logger = setup_logger("assembler")
HOSTNAME = socket.gethostname()

def assemble_telemetry_payload():
    """Polls all collectors and packages data into a standard SIEM schema."""
    logger.info("Gathering system telemetry...")
    
    try:
        payload = {
            "agent_id": HOSTNAME,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "metrics": {
                "system": collect_system_metrics(),
                "processes": collect_processes(),
                "network": collect_network_metrics(),
                "platform": collect_platform_metrics()
            }
        }
        logger.info("Successfully packaged telemetry payload.")
        return payload
        
    except Exception as e:
        logger.error(f"Failed to assemble telemetry payload: {e}")
        return None