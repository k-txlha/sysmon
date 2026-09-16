import datetime
import re
import socket
import uuid
from typing import Any, Dict, List
import psutil


class SystemCollector:
    """
    Cross-platform collector for universal system telemetry:
    - CPU & Memory utilization (psutil)
    - Running process inventory and resource statistics (psutil)
    - Host identity and network address resolution (socket, uuid)
    """

    def __init__(self):
        self._bytes_to_gb = 1024 ** 3

    def get_system_metrics(self) -> Dict[str, Any]:
        """Collects CPU and RAM statistics."""
        vm = psutil.virtual_memory()
        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "cpu_usage": psutil.cpu_percent(interval=0.5),
            "memory_usage": vm.percent,
            "memory_info": {
                "total_memory": f"{vm.total / self._bytes_to_gb:.2f} GB",
                "available_memory": f"{vm.available / self._bytes_to_gb:.2f} GB",
                "free_memory": f"{vm.free / self._bytes_to_gb:.2f} GB",
            },
        }

    def get_processes(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Collects process metrics, sorted by highest CPU usage."""
        processes = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                info = proc.info
                cpu_val = info.get("cpu_percent") or 0.0
                mem_val = info.get("memory_percent") or 0.0
                processes.append({
                    "pid": info.get("pid"),
                    "name": info.get("name") or "unknown",
                    "cpu_percent": f"{cpu_val:.1f}%",
                    "memory_percent": f"{mem_val:.2f}%",
                    "status": info.get("status", "unknown"),
                    "_sort_key": cpu_val,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        processes.sort(key=lambda p: p["_sort_key"], reverse=True)
        # Strip internal sorting key before returning
        for p in processes:
            p.pop("_sort_key", None)

        return processes[:limit] if limit else processes

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
            "ip-address": ip_address,
            "mac-address": mac_address,
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Gathers all cross-platform metrics into a combined dictionary."""
        return {
            "system": self.get_system_metrics(),
            "processes": self.get_processes(),
            "network": self.get_network_metrics(),
        }
