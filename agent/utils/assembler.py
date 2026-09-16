"""
agent/utils/assembler.py

Standardized Telemetry and Security Event Assembler for the Sysmon Agent.
Packages raw host telemetry, OS security logs, and agent health diagnostics into
discrete, versioned EventEnvelope objects complying with the Phase 0 data contract.
"""

from __future__ import annotations

import datetime
import os
import platform
import socket
import time
from typing import Any, Dict, List, Optional
import psutil

from collectors.base import BaseOSCollector
from collectors.common import SystemCollector
from models.envelope import EventEnvelope, SeverityLevel, AgentHealthTelemetry
from utils.logger import setup_logger

logger = setup_logger("assembler")


class TelemetryAssembler:
    """
    Coordinates telemetry gathering across collectors and packages events
    into standardized EDR EventEnvelopes.
    """

    def __init__(
        self,
        common_collector: SystemCollector,
        os_collector: BaseOSCollector,
        agent_id: Optional[str] = None,
        tenant_id: str = "default",
    ) -> None:
        self.common_collector = common_collector
        self.os_collector = os_collector
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

    def assemble(self, queue_depth: int = 0, dropped_events_total: int = 0, buffer_bytes: int = 0) -> List[Dict[str, Any]]:
        """
        Polls active collectors and generates a batch of standardized EventEnvelope dictionaries.
        """
        logger.info("Gathering and packaging system telemetry into EventEnvelopes...")
        envelopes: List[Dict[str, Any]] = []
        observed_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            # 1. Cross-platform metrics (CPU, RAM, Processes, Network)
            common_data = self.common_collector.get_metrics()
            system_data = common_data.get("system", {})
            processes_data = common_data.get("processes", [])
            network_data = common_data.get("network", {})

            # 2. OS-specific telemetry (Platform metadata & login events)
            os_logs = self.os_collector.get_logs()
            platform_data = os_logs.get("platform", {})
            login_attempts = platform_data.pop("login_attempts", [])

            # --- A. Telemetry Snapshot Event ---
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
                    "processes": processes_data,
                    "network": network_data,
                    "platform": platform_data,
                },
            )
            envelopes.append(snapshot_envelope.to_dict())

            # --- B. Individual Security Authentication Events ---
            for attempt in login_attempts:
                is_failure = str(attempt.get("status", "")).upper() == "FAILURE"
                severity = SeverityLevel.MEDIUM if is_failure else SeverityLevel.INFORMATIONAL

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

            # --- C. Agent Health & Diagnostics Event ---
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

            logger.info(f"Successfully packaged {len(envelopes)} standardized EventEnvelope(s).")
            return envelopes

        except Exception as e:
            logger.error(f"Failed to assemble telemetry envelopes: {e}")
            return []


def assemble_telemetry_payload(
    common_collector: Optional[SystemCollector] = None,
    os_collector: Optional[BaseOSCollector] = None,
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
                from collectors.windows import OSCollector
            elif os_type == "linux":
                from collectors.linux import OSCollector
            elif os_type == "darwin":
                from collectors.darwin import OSCollector
            else:
                raise NotImplementedError(f"Unsupported OS: {os_type}")
            os_collector = OSCollector()

    assembler = TelemetryAssembler(
        common_collector=common_collector,
        os_collector=os_collector,
        agent_id=agent_id,
    )
    return assembler.assemble(
        queue_depth=queue_depth,
        dropped_events_total=dropped_events_total,
        buffer_bytes=buffer_bytes,
    )
