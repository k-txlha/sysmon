import abc
import platform
from typing import Any, Dict, List


class BaseOSCollector(abc.ABC):
    """
    Abstract Base Class for operating system specific collectors.
    Each OS-specific implementation (Linux, Windows, macOS) must implement
    methods to retrieve platform-level telemetry and security authentication logs.
    """

    @abc.abstractmethod
    def get_platform_info(self) -> Dict[str, Any]:
        """
        Collects operating system and host metadata.
        Returns a dictionary containing OS name, version, release, and architecture.
        """
        pass

    @abc.abstractmethod
    def get_login_attempts(self, max_records: int = 50) -> List[Dict[str, Any]]:
        """
        Collects recent authentication and login attempts.
        Normalized to standard SIEM schema:
        [
            {
                "timestamp": "YYYY-MM-DD HH:MM:SS",
                "event_id": 4624 (SUCCESS) | 4625 (FAILURE),
                "status": "SUCCESS" | "FAILURE",
                "username": "user",
                "domain": "host_or_domain",
                "logon_type": "Interactive | SSH | PAM/sudo | ...",
                "source_ip": "1.2.3.4 | Local Machine"
            }
        ]
        """
        pass

    def get_base_platform_info(self) -> Dict[str, Any]:
        """
        Fallback/Universal platform metadata using Python's platform module.
        """
        return {
            "operating_system": platform.platform(),
            "operating_system_name": platform.system(),
            "operating_system_version": platform.version(),
            "machine_architecture": platform.machine(),
            "operating_system_release": platform.release(),
        }

    def get_logs(self, max_records: int = 50) -> Dict[str, Any]:
        """
        Returns OS-specific telemetry including platform details and security logs.
        """
        platform_info = self.get_platform_info()
        platform_info["login_attempts"] = self.get_login_attempts(max_records=max_records)
        return {"platform": platform_info}
