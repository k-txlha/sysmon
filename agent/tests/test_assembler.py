"""
Tests for Agent TelemetryAssembler.

Validates the assembler produces correct EventEnvelope types per the
Process Lifecycle Event Architecture v2:
- telemetry.snapshot: system/network/platform only (NO processes)
- process.snapshot / process.start / process.exit: separate first-class envelopes (§6)
- security.auth: per-login-attempt events
- agent.health: agent diagnostics
"""

from unittest.mock import MagicMock, patch
from agent.collectors.process import ProcessCollector
from agent.utils.assembler import TelemetryAssembler


def test_assembler_packages_envelopes():
    mock_common = MagicMock()
    mock_common.get_metrics.return_value = {
        "system": {"cpu_usage": 10.0, "memory_usage": 45.0},
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

    mock_process = MagicMock(spec=ProcessCollector)
    mock_process.collect_lifecycle_events.return_value = [
        {
            "event_type": "process.snapshot",
            "data": {
                "processes": [
                    {
                        "pid": 1,
                        "ppid": 0,
                        "name": "systemd",
                        "process_start_time": "2026-09-16T12:00:00Z",
                        "executable_path": "/usr/lib/systemd/systemd",
                        "command_line": ["/usr/lib/systemd/systemd"],
                        "sha256": "abc123",
                        "hash_status": "success",
                        "username": "root",
                        "working_directory": "/",
                    }
                ]
            },
        }
    ]

    assembler = TelemetryAssembler(
        common_collector=mock_common,
        os_collector=mock_os,
        process_collector=mock_process,
        agent_id="test-agent-99",
    )

    envelopes = assembler.assemble(queue_depth=5, dropped_events_total=1, buffer_bytes=2048)

    # Expect: 1 telemetry.snapshot + 1 process.snapshot + 1 security.auth + 1 agent.health = 4
    assert len(envelopes) == 4

    event_types = [e["event_type"] for e in envelopes]
    assert "telemetry.snapshot" in event_types
    assert "process.snapshot" in event_types
    assert "security.auth" in event_types
    assert "agent.health" in event_types

    # §6: telemetry.snapshot must NOT contain processes
    telem = next(e for e in envelopes if e["event_type"] == "telemetry.snapshot")
    assert "processes" not in telem["data"]
    assert "system" in telem["data"]
    assert "network" in telem["data"]

    # §6: process.snapshot is a separate envelope with process data
    proc_snap = next(e for e in envelopes if e["event_type"] == "process.snapshot")
    assert len(proc_snap["data"]["processes"]) == 1
    assert proc_snap["data"]["processes"][0]["name"] == "systemd"

    auth_env = next(e for e in envelopes if e["event_type"] == "security.auth")
    assert auth_env["severity"] == "medium"
    assert auth_env["data"]["username"] == "attacker"

    health_env = next(e for e in envelopes if e["event_type"] == "agent.health")
    assert health_env["data"]["queue_depth"] == 5


def test_assembler_with_lifecycle_events():
    """Verify assembler correctly wraps process.start and process.exit as separate envelopes."""
    mock_common = MagicMock()
    mock_common.get_metrics.return_value = {
        "system": {"cpu_usage": 5.0},
        "network": {"hostname": "host-2"},
    }

    mock_os = MagicMock()
    mock_os.get_logs.return_value = {"platform": {}}

    mock_process = MagicMock(spec=ProcessCollector)
    mock_process.collect_lifecycle_events.return_value = [
        {
            "event_type": "process.start",
            "data": {
                "pid": 16924,
                "ppid": 16872,
                "name": "brave.exe",
                "process_start_time": "2026-10-06T16:26:51Z",
                "executable_path": "C:\\Program Files\\brave.exe",
                "command_line": ["brave.exe", "--type=renderer"],
                "sha256": "fc51aa",
                "hash_status": "success",
                "username": "user",
                "working_directory": "C:\\",
            },
        },
        {
            "event_type": "process.exit",
            "data": {
                "pid": 8800,
                "process_start_time": "2026-10-06T16:26:21Z",
                "observed_exit_time": "2026-10-06T16:27:04Z",
            },
        },
    ]

    assembler = TelemetryAssembler(
        common_collector=mock_common,
        os_collector=mock_os,
        process_collector=mock_process,
        agent_id="test-agent-lifecycle",
    )

    envelopes = assembler.assemble()

    # telemetry.snapshot + process.start + process.exit + agent.health = 4
    assert len(envelopes) == 4

    event_types = [e["event_type"] for e in envelopes]
    assert "process.start" in event_types
    assert "process.exit" in event_types

    start_env = next(e for e in envelopes if e["event_type"] == "process.start")
    assert start_env["data"]["pid"] == 16924
    assert start_env["data"]["name"] == "brave.exe"

    exit_env = next(e for e in envelopes if e["event_type"] == "process.exit")
    assert exit_env["data"]["pid"] == 8800
    assert exit_env["data"]["observed_exit_time"] == "2026-10-06T16:27:04Z"


def test_assembler_with_no_lifecycle_events():
    """An empty lifecycle list (nothing changed) should not produce process envelopes."""
    mock_common = MagicMock()
    mock_common.get_metrics.return_value = {
        "system": {"cpu_usage": 5.0},
        "network": {"hostname": "host-3"},
    }

    mock_os = MagicMock()
    mock_os.get_logs.return_value = {"platform": {}}

    mock_process = MagicMock(spec=ProcessCollector)
    mock_process.collect_lifecycle_events.return_value = []  # Nothing changed

    assembler = TelemetryAssembler(
        common_collector=mock_common,
        os_collector=mock_os,
        process_collector=mock_process,
        agent_id="test-agent-empty",
    )

    envelopes = assembler.assemble()

    # telemetry.snapshot + agent.health only = 2
    assert len(envelopes) == 2
    event_types = [e["event_type"] for e in envelopes]
    assert "telemetry.snapshot" in event_types
    assert "agent.health" in event_types
    assert "process.snapshot" not in event_types
    assert "process.start" not in event_types
    assert "process.exit" not in event_types
