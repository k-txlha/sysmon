"""
agent/collectors/process.py

Dedicated Process Lifecycle Collector following the Process Lifecycle Event Architecture (v2).

Responsibilities:
- Enumerate ALL running processes on each scan cycle (psutil)
- Maintain previous process state across collection cycles
- Generate process.snapshot on first run / explicit resync
- Generate process.start for newly detected process instances
- Generate process.exit for disappeared process instances
- Use compound process identity (pid, process_start_time) to protect against PID reuse

Design Principles (from architecture document):
- Do NOT apply display limits before lifecycle comparison
- Do NOT create a new ProcessCollector per scan — reuse a single instance
- Do NOT use PID alone as process identity
- Do NOT put exited processes into the current-running snapshot
- An empty lifecycle-event list means "nothing changed", NOT "no processes are running"
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional, Tuple

import psutil

from utils.hash import FileHasher

logger = logging.getLogger("process_collector")

# Type alias: compound process identity key = (pid, process_start_time_iso)
ProcessIdentity = Tuple[int, str]


class ProcessCollector:
    """
    Stateful process lifecycle collector.

    Must be instantiated ONCE and reused across all collection cycles.
    Maintains an internal map of known process identities to detect starts and exits.

    Process identity is (pid, process_start_time) to guard against PID reuse.
    """

    def __init__(self) -> None:
        self._known_processes: Dict[ProcessIdentity, Dict[str, Any]] = {}
        self._hasher = FileHasher()
        self._first_run: bool = True

    def _extract_process_info(self, proc: psutil.Process) -> Optional[Dict[str, Any]]:
        """
        Safely extracts normalized telemetry from a psutil Process instance.

        Returns None if the process is inaccessible (e.g., zombie, access denied, vanished).
        """
        try:
            info = proc.as_dict(
                attrs=[
                    "pid",
                    "ppid",
                    "name",
                    "cpu_percent",
                    "memory_percent",
                    "status",
                    "create_time",
                    "exe",
                    "cmdline",
                    "username",
                    "cwd",
                ]
            )

            exe_path: str = info.get("exe") or ""

            # SHA-256 binary fingerprint with status tracking
            sha256_hash: str = ""
            hash_status: str = "success"
            if exe_path:
                sha256_hash = self._hasher.calculate_hash(exe_path)
                if sha256_hash.startswith("permission"):
                    hash_status = "permission_denied"
                elif sha256_hash.startswith("file_not"):
                    hash_status = "file_not_found"
                elif sha256_hash.startswith("unknown"):
                    hash_status = "unknown_error"
            else:
                hash_status = "no_executable"

            # Convert psutil epoch create_time to explicit UTC ISO-8601
            create_time = info.get("create_time")
            process_start_time: str = ""
            if create_time:
                process_start_time = datetime.datetime.fromtimestamp(
                    create_time, tz=datetime.timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

            return {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "unknown",
                "executable_path": exe_path,
                "command_line": info.get("cmdline") or [],
                "process_start_time": process_start_time,
                "sha256": sha256_hash,
                "hash_status": hash_status,
                "username": info.get("username"),
                "working_directory": info.get("cwd"),
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_percent": info.get("memory_percent") or 0.0,
                "status": info.get("status", "unknown"),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as exc:
            logger.debug("Failed to extract process info: %s", exc)
            return None

    def _enumerate_all_processes(
        self,
        filter_name: Optional[str] = None,
    ) -> Dict[ProcessIdentity, Dict[str, Any]]:
        """
        Enumerates ALL currently running processes.

        Returns a dict keyed by compound process identity (pid, process_start_time).
        No limit is applied here — limits are only for display/debug output.
        """
        current: Dict[ProcessIdentity, Dict[str, Any]] = {}
        for proc in psutil.process_iter():
            proc_info = self._extract_process_info(proc)
            if proc_info is None:
                continue

            if filter_name and proc_info.get("name") != filter_name:
                continue

            pid: int = proc_info["pid"]
            start_time: str = proc_info["process_start_time"]
            identity: ProcessIdentity = (pid, start_time)
            current[identity] = proc_info

        return current

    @staticmethod
    def _strip_runtime_fields(proc_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns a copy of process info suitable for event payloads,
        stripping transient runtime-only fields (cpu_percent, memory_percent, status).
        """
        exclude_keys = {"cpu_percent", "memory_percent", "status"}
        return {k: v for k, v in proc_info.items() if k not in exclude_keys}

    def collect_lifecycle_events(
        self,
        filter_name: Optional[str] = None,
        force_snapshot: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Core lifecycle collection method. Called once per scan cycle.

        Returns a list of structured lifecycle events:
        - On first run (or force_snapshot=True): a single process.snapshot event
        - On subsequent runs: zero or more process.start / process.exit events

        An empty list means "nothing changed during this cycle", NOT "no processes are running".

        Important: enumeration of ALL processes happens BEFORE lifecycle comparison.
        Limits are NOT applied before diffing.
        """
        current_processes = self._enumerate_all_processes(filter_name=filter_name)
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # --- Initial snapshot or explicit resync ---
        if self._first_run or force_snapshot:
            process_list = list(current_processes.values())
            snapshot_event: Dict[str, Any] = {
                "event_type": "process.snapshot",
                "data": {
                    "processes": [self._strip_runtime_fields(p) for p in process_list],
                },
            }
            self._known_processes = current_processes
            self._first_run = False
            logger.info(
                "Emitting process.snapshot with %d processes.", len(process_list)
            )
            return [snapshot_event]

        # --- Lifecycle diffing ---
        events: List[Dict[str, Any]] = []

        # Detect new process instances (PROCESS_START)
        new_identities = current_processes.keys() - self._known_processes.keys()
        for identity in new_identities:
            p_info = current_processes[identity]
            start_event: Dict[str, Any] = {
                "event_type": "process.start",
                "data": self._strip_runtime_fields(p_info),
            }
            events.append(start_event)
            logger.debug(
                "process.start: pid=%d name=%s",
                p_info.get("pid", -1),
                p_info.get("name", "?"),
            )

        # Detect exited process instances (PROCESS_EXIT)
        exited_identities = self._known_processes.keys() - current_processes.keys()
        for identity in exited_identities:
            prev_info = self._known_processes[identity]
            exit_event: Dict[str, Any] = {
                "event_type": "process.exit",
                "data": {
                    "pid": prev_info.get("pid", identity[0]),
                    "process_start_time": prev_info.get(
                        "process_start_time", identity[1]
                    ),
                    "observed_exit_time": now_iso,
                },
            }
            events.append(exit_event)
            logger.debug(
                "process.exit: pid=%d name=%s",
                prev_info.get("pid", -1),
                prev_info.get("name", "?"),
            )

        # Update known state for next cycle
        self._known_processes = current_processes

        if events:
            logger.info("Emitting %d process lifecycle events.", len(events))
        else:
            logger.debug("No process lifecycle changes detected this cycle.")

        return events
