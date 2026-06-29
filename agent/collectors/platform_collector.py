import platform
import win32evtlog
import xml.etree.ElementTree as ET
import datetime


def get_login_attempts(max_records=50):
    server = "localhost"
    log_type = "Security"

    # Open the event log
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events_extracted = []
    count = 0

    # Mapping common Windows Logon Types for SIEM visibility
    logon_types = {
        "2": "Interactive (Console/Keyboard)",
        "3": "Network (e.g., Shared Folder)",
        "4": "Batch (Scheduled Task)",
        "5": "Service (Background Process)",
        "7": "Unlock (Workstation Unlocked)",
        "10": "RemoteInteractive (RDP)",
    }

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events or count >= max_records:
            break

        for event in events:
            event_id = event.EventID & 0xFFFF

            # Catching both Success (4624) and Failure (4625)
            if event_id in [4624, 4625]:
                data = event.StringInserts
                if not data:
                    continue

                # Windows event data structures differ slightly between 4624 and 4625,
                # but target user, domain, and logon type are consistently located:
                target_user = data[5]
                target_domain = data[6]
                logon_type_code = data[8]
                logon_type_desc = logon_types.get(
                    logon_type_code, f"Unknown ({logon_type_code})"
                )

                # IP Address initiating the connection (crucial for a SIEM!)
                # Index 18 for 4624, Index 19 for 4625 usually holds the Source Network Address
                try:
                    source_ip = data[18] if event_id == 4624 else data[19]
                except IndexError:
                    source_ip = "Unknown"

                # Filter out machine noise (system accounts ending in $)
                if target_user.endswith("$") or target_user in [
                    "SYSTEM",
                    "LOCAL SERVICE",
                    "NETWORK SERVICE",
                ]:
                    continue

                # Constructing a clean SIEM-ready data object
                log_entry = {
                    "timestamp": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_id": event_id,
                    "status": "SUCCESS" if event_id == 4624 else "FAILURE",
                    "username": target_user,
                    "domain": target_domain,
                    "logon_type": logon_type_desc,
                    "source_ip": (
                        source_ip
                        if source_ip.strip() not in ["-", "127.0.0.1"]
                        else "Local Machine"
                    ),
                }

                events_extracted.append(log_entry)
                count += 1

                if count >= max_records:
                    break

    return events_extracted


def collect_platform_metrics():
    attemps = get_login_attempts(max_records=10)
    return {
        "operating_system": platform.platform(),
        "operating_system_name": platform.system(),
        "operating_system_version": platform.version(),
        "machine_architecture": platform.machine(),
        "operating_system_release": platform.release(),
        "login_attempts": attemps,
    }

