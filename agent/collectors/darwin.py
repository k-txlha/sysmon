import datetime
import platform
import subprocess
from typing import Any, Dict, List
from collectors.base import BaseOSCollector
from utils.logger import setup_logger

logger = setup_logger("collector_darwin")


class DarwinCollector(BaseOSCollector):
    """
    macOS (Darwin) telemetry and security event collector:
    - Queries macOS system release, build, and hardware architecture
    - Extracts authentication events via Unified Logging System (`log show`)
    """

    def __init__(self):
        self._hostname = platform.node()

    def get_platform_info(self) -> Dict[str, Any]:
        """Collects macOS platform, version, and architecture details."""
        mac_ver = platform.mac_ver()[0]
        os_version = f"macOS {mac_ver}" if mac_ver else platform.version()

        return {
            "operating_system": f"macOS ({platform.platform()})",
            "operating_system_name": platform.system(),
            "operating_system_version": os_version,
            "machine_architecture": platform.machine(),
            "operating_system_release": platform.release(),
        }

    def get_login_attempts(self, max_records: int = 50) -> List[Dict[str, Any]]:
        """
        Reads recent login attempts from macOS unified logs.
        """
        events: List[Dict[str, Any]] = []

        try:
            # Query the unified log stream for Authorization / Security subsystem events in past 5 minutes
            cmd = [
                "log", "show",
                "--predicate", 'process == "loginwindow" or process == "sshd" or process == "sudo"',
                "--last", "5m",
                "--style", "syslog",
            ]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    # Parse relevant SSH / auth entries
                    if "Failed" in line or "failure" in line:
                        events.append({
                            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                            "event_id": 4625,
                            "status": "FAILURE",
                            "username": "unknown",
                            "domain": self._hostname,
                            "logon_type": "macOS Auth",
                            "source_ip": "Local Machine",
                        })
                    elif "Accepted" in line or "success" in line:
                        events.append({
                            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                            "event_id": 4624,
                            "status": "SUCCESS",
                            "username": "unknown",
                            "domain": self._hostname,
                            "logon_type": "macOS Auth",
                            "source_ip": "Local Machine",
                        })

                    if len(events) >= max_records:
                        break

        except Exception as e:
            logger.debug(f"macOS log collection notice: {e}")

        return events


# Standard alias for dynamic OS import
OSCollector = DarwinCollector
