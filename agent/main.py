import json
import time

from collectors.system_collector import collect_system_metrics
from collectors.process_collector import collect_processes
from collectors.network_collector import collect_network_metrics
from collectors.platform_collector import collect_platform_metrics

def main():
    while True:
        payload = {
            "system": collect_system_metrics(),
            "processes": collect_processes(),
            "network": collect_network_metrics(),
            "platform": collect_platform_metrics()
        }

        print(json.dumps(payload, indent=2))

        time.sleep(5)

if __name__ == "__main__":
    main()
