import psutil
from datetime import datetime

def collect_system_metrics():
    bytes_to_GB = 1024 ** 3
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "memory_info": {
            "total_memory": f"{psutil.virtual_memory().total / bytes_to_GB:.2f} GB",
            "available_memory": f"{psutil.virtual_memory().available / bytes_to_GB:.2f} GB",
            "free_memory": f"{psutil.virtual_memory().free / bytes_to_GB:.2f} GB"
        }
    }
