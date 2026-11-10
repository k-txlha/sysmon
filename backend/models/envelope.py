"""
backend/models/envelope.py

Standardized EDR Event Envelope for the Sysmon Ingestion Gateway (Phase 0/1).
Enforces schema validation, tenant/host identification, and UTC timestamping.
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventEnvelope(BaseModel):
    """
    Standardized EDR Event Envelope according to the Sysmon Blueprint (Section 3).
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
        description="Stable identifier for the host machine",
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
        ...,
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
        description="Sensor source identifier (e.g., 'windows_agent', 'linux_agent')",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.INFORMATIONAL,
        description="Severity classification",
    )
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Payload containing event-specific data",
    )


class IngestionBatchRequest(BaseModel):
    """Container for batch envelope submissions."""

    events: List[EventEnvelope] = Field(
        ...,
        description="List of standardized EventEnvelopes",
    )
