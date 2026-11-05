"""
agent/utils/assembler.py

Standardized Telemetry and Security Event Assembler for the Sysmon Agent.

Packages raw host telemetry, OS security logs, process lifecycle events,
and agent health diagnostics into discrete, versioned EventEnvelope objects.

Architecture (per Process Lifecycle Event Architecture v2, §6):
- telemetry.snapshot contains ONLY system/network/platform data (no processes)
- process.snapshot, process.start, process.exit are first-class EventEnvelope types
- An empty process lifecycle list means "nothing changed", NOT "no processes running"
"""

from __future__ import annotations

import datetime
import os
import platform
import socket
import time
from typing import Any, Dict, List, Optional

import psutil

from agent.collectors.base import BaseOSCollector
from agent.collectors.common import SystemCollector
from agent.collectors.process import ProcessCollector
from agent.models.envelope import EventEnvelope, SeverityLevel, AgentHealthTelemetry
from agent.utils.logger import setup_logger

logger = setup_logger("assembler")

# Mapping from raw lifecycle event_type to EventEnvelope event_type
_PROCESS_EVENT_TYPE_MAP: Dict[str, str] = {
    "process.snapshot": "process.snapshot",
    "process.start": "process.start",
    "process.exit": "process.exit",
}


class TelemetryAssembler:
    """
    Coordinates telemetry gathering across collectors and packages events
    into standardized EDR EventEnvelopes.

    Process lifecycle events are emitted as separate, first-class EventEnvelopes
    rather than being embedded inside telemetry.snapshot.
    """

    def __init__(
        self,
        common_collector: SystemCollector,
        os_collector: BaseOSCollector,
        process_collector: Optional[ProcessCollector] = None,
        agent_id: Optional[str] = None,
        tenant_id: str = "default",
    ) -> None:
        self.common_collector = common_collector
        self.os_collector = os_collector
        self.process_collector = process_collector or ProcessCollector()
        self.host_id = socket.gethostname()
        self.agent_id = agent_id or self.host_id
        self.tenant_id = tenant_id
        self.source = f"{platform.system().lower()}_agent"
        self._sequence = 0
        self._start_time = time.time()
        self._process = psutil.Process(os.getpid())

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def assemble(
        self, queue_depth: int = 0, dropped_events_total: int = 0, buffer_bytes: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Polls active collectors and generates a batch of standardized EventEnvelope dictionaries.

        Envelope types emitted:
        - telemetry.snapshot: System metrics, network info, OS platform data (NO processes)
        - process.snapshot: Full process list on first run / resync
        - process.start: Individual new process detection
        - process.exit: Individual process disappearance detection
        - security.auth: Per-login-attempt security events
        - agent.health: Agent self-diagnostics
        """
        logger.info("Gathering and packaging system telemetry into EventEnvelopes...")
        envelopes: List[Dict[str, Any]] = []
        observed_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            # ──────────────────────────────────────────────────────────────────
            # 1. Cross-platform metrics (CPU, RAM, Network) — NO processes
            # ──────────────────────────────────────────────────────────────────
            common_data = self.common_collector.get_metrics()
            system_data = common_data.get("system", {})
            network_data = common_data.get("network", {})

            # 2. OS-specific telemetry (Platform metadata & login events)
            os_logs = self.os_collector.get_logs()
            platform_data = os_logs.get("platform", {})
            login_attempts = platform_data.pop("login_attempts", [])

            # --- A. Telemetry Snapshot Event (system/network/platform only) ---
            snapshot_envelope = EventEnvelope(
                tenant_id=self.tenant_id,
                host_id=self.host_id,
                agent_id=self.agent_id,
                event_type="telemetry.snapshot",
                observed_at=observed_now,
                sequence=self._next_sequence(),
                source=self.source,
                severity=SeverityLevel.INFORMATIONAL,
                data={
                    "system": system_data,
                    "network": network_data,
                    "platform": platform_data,
                },
            )
            envelopes.append(snapshot_envelope.to_dict())

            # ──────────────────────────────────────────────────────────────────
            # 3. Process Lifecycle Events — first-class EventEnvelopes (§6)
            # ──────────────────────────────────────────────────────────────────
            process_events = self.process_collector.collect_lifecycle_events()
            for pe in process_events:
                raw_event_type = pe.get("event_type", "")
                envelope_event_type = _PROCESS_EVENT_TYPE_MAP.get(
                    raw_event_type, raw_event_type
                )

                process_envelope = EventEnvelope(
                    tenant_id=self.tenant_id,
                    host_id=self.host_id,
                    agent_id=self.agent_id,
                    event_type=envelope_event_type,
                    observed_at=observed_now,
                    sequence=self._next_sequence(),
                    source=self.source,
                    severity=SeverityLevel.INFORMATIONAL,
                    data=pe.get("data", {}),
                )
                envelopes.append(process_envelope.to_dict())

            # ──────────────────────────────────────────────────────────────────
            # 4. Individual Security Authentication Events
            # ──────────────────────────────────────────────────────────────────
            for attempt in login_attempts:
                is_failure = str(attempt.get("status", "")).upper() == "FAILURE"
                severity = (
                    SeverityLevel.MEDIUM if is_failure else SeverityLevel.INFORMATIONAL
                )

                auth_observed = attempt.get("timestamp")
                if not auth_observed:
                    auth_observed = observed_now
                elif not (auth_observed.endswith("Z") or "+" in auth_observed):
                    auth_observed = f"{auth_observed}Z"

                auth_envelope = EventEnvelope(
                    tenant_id=self.tenant_id,
                    host_id=self.host_id,
                    agent_id=self.agent_id,
                    event_type="security.auth",
                    observed_at=auth_observed,
                    sequence=self._next_sequence(),
                    source=self.source,
                    severity=severity,
                    data=attempt,
                )
                envelopes.append(auth_envelope.to_dict())

            # ──────────────────────────────────────────────────────────────────
            # 5. Agent Health & Diagnostics Event
            # ──────────────────────────────────────────────────────────────────
            try:
                mem_info = self._process.memory_info()
                rss_mb = round(mem_info.rss / (1024 * 1024), 2)
                cpu_pct = round(self._process.cpu_percent(interval=None), 2)
            except Exception:
                rss_mb = 0.0
                cpu_pct = 0.0

            uptime = round(time.time() - self._start_time, 2)
            health_telemetry = AgentHealthTelemetry(
                cpu_percent=cpu_pct,
                memory_rss_mb=rss_mb,
                queue_depth=queue_depth,
                dropped_events_total=dropped_events_total,
                buffer_bytes=buffer_bytes,
                uptime_seconds=uptime,
            )

            health_envelope = EventEnvelope(
                tenant_id=self.tenant_id,
                host_id=self.host_id,
                agent_id=self.agent_id,
                event_type="agent.health",
                observed_at=observed_now,
                sequence=self._next_sequence(),
                source=self.source,
                severity=SeverityLevel.INFORMATIONAL,
                data=health_telemetry.model_dump(),
            )
            envelopes.append(health_envelope.to_dict())

            logger.info(
                f"Successfully packaged {len(envelopes)} standardized EventEnvelope(s)."
            )
            return envelopes

        except Exception as e:
            logger.error(f"Failed to assemble telemetry envelopes: {e}")
            return []


def assemble_telemetry_payload(
    common_collector: Optional[SystemCollector] = None,
    os_collector: Optional[BaseOSCollector] = None,
    process_collector: Optional[ProcessCollector] = None,
    agent_id: Optional[str] = None,
    queue_depth: int = 0,
    dropped_events_total: int = 0,
    buffer_bytes: int = 0,
) -> List[Dict[str, Any]]:
    """
    Functional helper to assemble a batch of telemetry envelopes.
    Creates default instances based on detected OS if collectors are not passed.
    """
    if common_collector is None or os_collector is None:
        os_type = platform.system().lower()
        if common_collector is None:
            common_collector = SystemCollector()
        if os_collector is None:
            if os_type == "windows":
                from agent.collectors.windows import OSCollector
            elif os_type == "linux":
                from agent.collectors.linux import OSCollector
            elif os_type == "darwin":
                from agent.collectors.darwin import OSCollector
            else:
                raise NotImplementedError(f"Unsupported OS: {os_type}")
            os_collector = OSCollector()

    if process_collector is None:
        process_collector = ProcessCollector()

    assembler = TelemetryAssembler(
        common_collector=common_collector,
        os_collector=os_collector,
        process_collector=process_collector,
        agent_id=agent_id,
    )
    return assembler.assemble(
        queue_depth=queue_depth,
        dropped_events_total=dropped_events_total,
        buffer_bytes=buffer_bytes,
    )
