"""
agent/models/envelope.py

Standardized EDR Event Envelope according to the Sysmon Blueprint (Section 3).
Provides a stable, versioned contract for all endpoint telemetry, security events,
and agent health diagnostics.
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentHealthTelemetry(BaseModel):
    """Health, resource utilization, and queue statistics for the local agent process."""

    model_config = ConfigDict(extra="allow")

    cpu_percent: float = Field(..., description="Agent process CPU percentage")
    memory_rss_mb: float = Field(..., description="Agent resident set size memory in MB")
    queue_depth: int = Field(0, description="Number of events currently queued in local disk buffer")
    dropped_events_total: int = Field(0, description="Total events dropped since agent start")
    buffer_bytes: int = Field(0, description="Disk usage of local buffer in bytes")
    uptime_seconds: float = Field(..., description="Agent uptime in seconds")


class EventEnvelope(BaseModel):
    """
    Standardized EDR Telemetry and Security Event Envelope.

    Required fields support deduplication, tracing, tenant isolation,
    and investigation workflows across backend, ClickHouse, and detection workers.
    """

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique UUIDv4 identifying this discrete event instance",
    )
    schema_version: int = Field(
        default=1,
        description="Version of the event schema for evolution and migrations",
    )
    tenant_id: str = Field(
        default="default",
        description="Tenant identifier for multi-tenant isolation",
    )
    host_id: str = Field(
        ...,
        description="Stable identifier for the host machine (e.g., hostname or machine GUID)",
    )
    agent_id: str = Field(
        ...,
        description="Unique agent instance identifier",
    )
    event_type: str = Field(
        ...,
        description="Dot-notated event type (e.g., 'telemetry.snapshot', 'security.auth', 'agent.health')",
    )
    observed_at: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="RFC3339 UTC timestamp recorded at the endpoint sensor",
    )
    received_at: Optional[str] = Field(
        default=None,
        description="RFC3339 UTC timestamp stamped upon arrival at backend ingestion gateway",
    )
    sequence: int = Field(
        default=0,
        description="Monotonically increasing sequence number per agent session",
    )
    source: str = Field(
        ...,
        description="Sensor source identifier (e.g., 'windows_agent', 'linux_agent', 'darwin_agent')",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.INFORMATIONAL,
        description="Severity classification for prioritization",
    )
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Payload containing event-specific telemetry or security event details",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts the envelope model to a JSON-serializable dictionary."""
        return self.model_dump(mode="json")


class IngestionBatchRequest(BaseModel):
    """Container for batch envelope submissions."""

    events: list[EventEnvelope] = Field(
        ...,
        description="List of standardized EventEnvelopes",
    )

