"""
agent/collectors/common.py

Cross-platform collector for universal system metrics and network identity:
- CPU & RAM utilization statistics (psutil)
- Host identity and network address resolution (socket, uuid)

Process lifecycle collection has been moved to collectors/process.py (ProcessCollector)
per the Process Lifecycle Event Architecture v2 guidelines.
"""

from __future__ import annotations

import datetime
import re
import socket
import uuid
from typing import Any, Dict

import psutil


class SystemCollector:
    """
    Cross-platform collector for general system telemetry:
    - CPU & Memory utilization
    - Host identity and network resolution

    Process lifecycle tracking is handled by ProcessCollector (collectors/process.py).
    """

    def __init__(self) -> None:
        self._bytes_to_gb = 1024 ** 3

    def get_system_metrics(self) -> Dict[str, Any]:
        """Collects CPU and RAM statistics."""
        vm = psutil.virtual_memory()
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cpu_usage": psutil.cpu_percent(interval=0.1),
            "memory_usage": vm.percent,
            "memory_info": {
                "total_memory": f"{vm.total / self._bytes_to_gb:.2f} GB",
                "available_memory": f"{vm.available / self._bytes_to_gb:.2f} GB",
                "free_memory": f"{vm.free / self._bytes_to_gb:.2f} GB",
            },
        }

    def get_network_metrics(self) -> Dict[str, str]:
        """Collects network identification metrics (hostname, IP, MAC)."""
        hostname = socket.gethostname()
        ip_address = "127.0.0.1"

        try:
            # Connect to a dummy external address (does not send data) to discover the outbound interface IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
        except Exception:
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = "127.0.0.1"

        mac_address = ":".join(re.findall("..", "%012x" % uuid.getnode()))

        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Gathers all cross-platform metrics into a combined dictionary."""
        return {
            "system": self.get_system_metrics(),
            "network": self.get_network_metrics(),
        }
