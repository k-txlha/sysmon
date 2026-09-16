import datetime
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from collectors.base import BaseOSCollector
from utils.logger import setup_logger

logger = setup_logger("collector_linux")

AUTH_LOG_PATHS = [
    Path("/var/log/auth.log"),  # Debian / Ubuntu / Kali
    Path("/var/log/secure"),  # RHEL / CentOS / Fedora / Rocky / Alma
    Path("/var/log/messages"),  # Generic Linux syslog
]


class LinuxCollector(BaseOSCollector):
    """
    Linux-specific telemetry and security event collector:
    - Parses Linux distribution info (/etc/os-release) & kernel details
    - Parses authentication & security logs (SSH logins, PAM/sudo events)
    - Normalizes events to SIEM schema (Event IDs 4624/4625, status, source IP)
    """

    def __init__(self):
        self._file_offsets: Dict[str, int] = {}
        self._hostname = platform.node()

    def get_platform_info(self) -> Dict[str, Any]:
        """Collects Linux-specific OS metadata and distribution details."""
        distro_name = ""
        distro_version = ""

        # Try reading /etc/os-release
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                with open(os_release, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            distro_name = line.strip().split("=", 1)[1].strip("\"'")
                        elif line.startswith("VERSION_ID="):
                            distro_version = line.strip().split("=", 1)[1].strip("\"'")
            except Exception as e:
                logger.debug(f"Could not read /etc/os-release: {e}")

        # Fallback to standard platform calls
        base_os = distro_name if distro_name else platform.platform()
        version = distro_version if distro_version else platform.version()

        return {
            "operating_system": base_os,
            "operating_system_name": platform.system(),
            "operating_system_version": version,
            "machine_architecture": platform.machine(),
            "operating_system_release": platform.release(),
        }

    def _find_auth_log(self) -> Optional[Path]:
        """Locates the active authentication log file."""
        for path in AUTH_LOG_PATHS:
            if path.exists() and os.access(path, os.R_OK):
                return path
        return None

    def _parse_timestamp(self, ts_raw: str) -> str:
        """Converts syslog or ISO-8601 timestamps to YYYY-MM-DD HH:MM:SS."""
        ts_raw = ts_raw.strip()
        current_year = datetime.datetime.utcnow().year

        # Format 1: ISO 8601 (e.g. 2026-09-16T14:30:00.123456+00:00 or 2026-09-16T14:30:00Z)
        try:
            cleaned_iso = ts_raw.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(cleaned_iso)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        # Format 2: Syslog standard (e.g. Sep 16 14:30:00)
        try:
            dt = datetime.datetime.strptime(
                f"{current_year} {ts_raw}", "%Y %b %d %H:%M:%S"
            )
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        # Fallback: Current UTC timestamp
        return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single log line from auth.log/secure and extracts security event metadata.
        Standardizes to SIEM schema (Event ID 4624 for Success, 4625 for Failure).
        """
        line = line.strip()
        if not line:
            return None

        # 1. SSH Successful login (password, publickey, keyboard-interactive)
        # e.g.: Sep 16 14:30:00 host sshd[1234]: Accepted password for root from 192.168.1.100 port 54321 ssh2
        ssh_accepted = re.search(
            r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)",
            line,
        )
        if ssh_accepted:
            ts_raw, host, auth_method, user, ip = ssh_accepted.groups()
            return {
                "timestamp": self._parse_timestamp(ts_raw),
                "event_id": 4624,
                "status": "SUCCESS",
                "username": user,
                "domain": host or self._hostname,
                "logon_type": f"SSH ({auth_method})",
                "source_ip": ip,
            }

        # 2. SSH Failed login
        # e.g.: Sep 16 14:30:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
        # or: Failed password for root from 192.168.1.100 port 54321 ssh2
        ssh_failed = re.search(
            r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)",
            line,
        )
        if ssh_failed:
            ts_raw, host, auth_method, user, ip = ssh_failed.groups()
            return {
                "timestamp": self._parse_timestamp(ts_raw),
                "event_id": 4625,
                "status": "FAILURE",
                "username": user,
                "domain": host or self._hostname,
                "logon_type": f"SSH ({auth_method})",
                "source_ip": ip,
            }

        # 3. SSH Invalid User attempt
        # e.g.: Sep 16 14:30:00 host sshd[1234]: Invalid user testuser from 192.168.1.100 port 54321
        ssh_invalid = re.search(
            r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(\S+)\s+sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)",
            line,
        )
        if ssh_invalid:
            ts_raw, host, user, ip = ssh_invalid.groups()
            return {
                "timestamp": self._parse_timestamp(ts_raw),
                "event_id": 4625,
                "status": "FAILURE",
                "username": user,
                "domain": host or self._hostname,
                "logon_type": "SSH (Invalid User)",
                "source_ip": ip,
            }

        # 4. PAM / Sudo Authentication Failure
        # e.g.: Sep 16 14:30:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 ... user=alice
        pam_failure = re.search(
            r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(\S+)\s+(?:sudo|su|sshd|login)\[?\d*\]?:\s+pam_unix\([^)]+\):\s+authentication failure;.*user=(\S*)",
            line,
        )
        if pam_failure:
            ts_raw, host, user = pam_failure.groups()
            return {
                "timestamp": self._parse_timestamp(ts_raw),
                "event_id": 4625,
                "status": "FAILURE",
                "username": user or "unknown",
                "domain": host or self._hostname,
                "logon_type": "PAM/sudo",
                "source_ip": "Local Machine",
            }

        # 5. Sudo Command Execution (Privileged action)
        # e.g.: Sep 16 14:30:00 host sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
        sudo_cmd = re.search(
            r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(\S+)\s+sudo\[?\d*\]?:\s+(\S+)\s+:.*COMMAND=(.*)",
            line,
        )
        if sudo_cmd:
            ts_raw, host, user, cmd = sudo_cmd.groups()
            return {
                "timestamp": self._parse_timestamp(ts_raw),
                "event_id": 4624,
                "status": "SUCCESS",
                "username": user,
                "domain": host or self._hostname,
                "logon_type": f"Sudo Command ({cmd.strip()[:30]})",
                "source_ip": "Local Machine",
            }

        return None

    def _read_from_journalctl(self, max_records: int) -> List[str]:
        """Fallback: Reads recent authentication logs from systemd journal if available."""
        try:
            res = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    "ssh",
                    "-u",
                    "sshd",
                    "-u",
                    "sudo",
                    "-n",
                    str(max_records),
                    "--no-pager",
                    "--output=short-iso",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout:
                return res.stdout.splitlines()
        except Exception as e:
            logger.debug(f"journalctl fallback unavailable: {e}")
        return []

    def get_login_attempts(self, max_records: int = 50) -> List[Dict[str, Any]]:
        """
        Extracts recent authentication events from Linux log files.
        Maintains file offsets across collection cycles to avoid duplicate reporting.
        """
        events: List[Dict[str, Any]] = []
        log_path = self._find_auth_log()

        if not log_path:
            # Fallback to journalctl if accessible
            lines = self._read_from_journalctl(max_records)
            for line in lines:
                event = self.parse_log_line(line)
                if event:
                    events.append(event)
                    if len(events) >= max_records:
                        break
            return events

        path_str = str(log_path)
        try:
            file_size = log_path.stat().st_size
            last_offset = self._file_offsets.get(path_str, 0)

            # Handle log rotation: if current file is smaller than previous offset, reset
            if file_size < last_offset:
                last_offset = 0

            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                # On initial run, read from near end if file is very large
                if last_offset == 0 and file_size > 100_000:
                    f.seek(max(0, file_size - 50_000))
                    f.readline()  # Discard partial line
                else:
                    f.seek(last_offset)

                for line in f:
                    event = self.parse_log_line(line)
                    if event:
                        events.append(event)
                        if len(events) >= max_records:
                            break

                self._file_offsets[path_str] = f.tell()

        except PermissionError:
            logger.warning(
                f"Permission denied reading {log_path}. Ensure agent runs with appropriate permissions (e.g., adm group or root)."
            )
        except Exception as e:
            logger.error(f"Error collecting Linux login attempts: {e}")

        return events


# Standard alias for dynamic OS import
OSCollector = LinuxCollector
