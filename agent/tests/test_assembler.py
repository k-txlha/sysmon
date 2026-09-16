"""
Tests for Agent TelemetryAssembler.
"""

from unittest.mock import MagicMock
from utils.assembler import TelemetryAssembler


def test_assembler_packages_envelopes():
    mock_common = MagicMock()
    mock_common.get_metrics.return_value = {
        "system": {"cpu_usage": 10.0, "memory_usage": 45.0},
        "processes": [{"pid": 1, "name": "systemd"}],
        "network": {"hostname": "test-host", "ip-address": "10.0.0.1"},
    }

    mock_os = MagicMock()
    mock_os.get_logs.return_value = {
        "platform": {
            "operating_system": "Linux 5.15",
            "login_attempts": [
                {
                    "timestamp": "2026-09-16T14:00:00Z",
                    "event_id": 4625,
                    "status": "FAILURE",
                    "username": "attacker",
                    "domain": "CORP",
                    "logon_type": "Interactive",
                    "source_ip": "192.168.1.50",
                }
            ],
        }
    }

    assembler = TelemetryAssembler(
        common_collector=mock_common,
        os_collector=mock_os,
        agent_id="test-agent-99",
    )

    envelopes = assembler.assemble(queue_depth=5, dropped_events_total=1, buffer_bytes=2048)

    # Expect: 1 snapshot envelope + 1 auth event envelope + 1 health envelope = 3 envelopes
    assert len(envelopes) == 3

    event_types = [e["event_type"] for e in envelopes]
    assert "telemetry.snapshot" in event_types
    assert "security.auth" in event_types
    assert "agent.health" in event_types

    auth_env = next(e for e in envelopes if e["event_type"] == "security.auth")
    assert auth_env["severity"] == "medium"
    assert auth_env["data"]["username"] == "attacker"

    health_env = next(e for e in envelopes if e["event_type"] == "agent.health")
    assert health_env["data"]["queue_depth"] == 5
