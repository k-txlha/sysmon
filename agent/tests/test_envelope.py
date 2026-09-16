"""
Tests for Agent EventEnvelope schema and data contracts.
"""

import datetime
import pytest
from pydantic import ValidationError

from models.envelope import EventEnvelope, SeverityLevel, AgentHealthTelemetry


def test_valid_event_envelope_creation():
    env = EventEnvelope(
        host_id="test-host-01",
        agent_id="test-agent-01",
        event_type="telemetry.snapshot",
        observed_at="2026-09-16T14:30:00.000Z",
        sequence=1,
        source="windows_agent",
        severity=SeverityLevel.INFORMATIONAL,
        data={"cpu": 12.5},
    )

    assert env.event_id is not None
    assert len(env.event_id) == 36  # UUID length
    assert env.schema_version == 1
    assert env.tenant_id == "default"
    assert env.host_id == "test-host-01"
    assert env.agent_id == "test-agent-01"
    assert env.event_type == "telemetry.snapshot"
    assert env.severity == SeverityLevel.INFORMATIONAL
    assert env.data == {"cpu": 12.5}


def test_event_envelope_serialization():
    env = EventEnvelope(
        host_id="host-abc",
        agent_id="agent-xyz",
        event_type="security.auth",
        source="linux_agent",
        severity=SeverityLevel.HIGH,
        data={"user": "root", "status": "FAILURE"},
    )
    d = env.to_dict()
    assert isinstance(d, dict)
    assert d["severity"] == "high"
    assert d["data"]["user"] == "root"
    assert d["source"] == "linux_agent"


def test_missing_required_fields_raises_validation_error():
    with pytest.raises(ValidationError):
        # Missing host_id, agent_id, event_type, source
        EventEnvelope.model_validate({})


def test_agent_health_telemetry_model():
    health = AgentHealthTelemetry(
        cpu_percent=1.2,
        memory_rss_mb=45.6,
        queue_depth=10,
        dropped_events_total=0,
        buffer_bytes=1024,
        uptime_seconds=3600.0,
    )
    assert health.cpu_percent == 1.2
    assert health.queue_depth == 10
    assert health.memory_rss_mb == 45.6
