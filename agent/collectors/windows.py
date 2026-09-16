import platform
from typing import Any, Dict, List
from collectors.base import BaseOSCollector
from utils.logger import setup_logger

logger = setup_logger("collector_windows")

try:
    import win32evtlog
except ImportError:
    win32evtlog = None
    logger.warning(
        "pywin32 (win32evtlog) module not found. Windows Event log collection will be disabled."
    )


class WindowsCollector(BaseOSCollector):
    """
    Windows-specific telemetry and security event collector:
    - Queries Windows platform and OS version details
    - Reads Windows Event Log (Security channel) for Event IDs 4624 (Logon Success) and 4625 (Logon Failure)
    - Maps logon types (Interactive, Network, RDP, Service) and extracts source IP
    """

    LOGON_TYPES = {
        "2": "Interactive (Console/Keyboard)",
        "3": "Network (e.g., Shared Folder)",
        "4": "Batch (Scheduled Task)",
        "5": "Service (Background Process)",
        "7": "Unlock (Workstation Unlocked)",
        "10": "RemoteInteractive (RDP)",
    }

    SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

    def get_platform_info(self) -> Dict[str, Any]:
        """Collects Windows platform and OS details."""
        return {
            "operating_system": platform.platform(),
            "operating_system_name": platform.system(),
            "operating_system_version": platform.version(),
            "machine_architecture": platform.machine(),
            "operating_system_release": platform.release(),
        }

    def get_login_attempts(self, max_records: int = 50) -> List[Dict[str, Any]]:
        """
        Reads recent Security event logs from the Windows Event Log API.
        """
        if not win32evtlog:
            logger.warning(
                "win32evtlog is unavailable. Skipping Windows Security log extraction."
            )
            return []

        server = "localhost"
        log_type = "Security"
        events_extracted = []

        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            count = 0

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events or count >= max_records:
                    break

                for event in events:
                    event_id = event.EventID & 0xFFFF

                    # 4624 = Success, 4625 = Failure
                    if event_id in [4624, 4625]:
                        data = event.StringInserts
                        if not data:
                            continue

                        # StringInserts standard indices for 4624 and 4625
                        target_user = data[5] if len(data) > 5 else "unknown"
                        target_domain = data[6] if len(data) > 6 else "unknown"
                        logon_type_code = data[8] if len(data) > 8 else ""
                        logon_type_desc = self.LOGON_TYPES.get(
                            logon_type_code,
                            (
                                f"LogonType-{logon_type_code}"
                                if logon_type_code
                                else "Unknown"
                            ),
                        )

                        # Source Network IP (Index 18 for 4624, Index 19 for 4625)
                        try:
                            source_ip = data[18] if event_id == 4624 else data[19]
                        except IndexError:
                            source_ip = "Unknown"

                        # Filter out machine noise (system accounts ending in $)
                        if (
                            target_user.endswith("$")
                            or target_user.upper() in self.SYSTEM_ACCOUNTS
                        ):
                            continue

                        log_entry = {
                            "timestamp": event.TimeGenerated.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "event_id": event_id,
                            "status": "SUCCESS" if event_id == 4624 else "FAILURE",
                            "username": target_user,
                            "domain": target_domain,
                            "logon_type": logon_type_desc,
                            "source_ip": (
                                source_ip
                                if source_ip.strip() not in ["-", "127.0.0.1", "::1"]
                                else "Local Machine"
                            ),
                        }

                        events_extracted.append(log_entry)
                        count += 1

                        if count >= max_records:
                            break

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            logger.error(f"Failed to read Windows Security Event Log: {e}")

        return events_extracted


# Standard alias for dynamic OS import
OSCollector = WindowsCollector
