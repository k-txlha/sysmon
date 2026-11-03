"""
agent/tests/test_process.py

Unit tests for the Process Lifecycle Collector (ProcessCollector) per the
Process Lifecycle Event Architecture v2 specification.

Validates:
- §7: Initial process.snapshot at startup
- §8: process.start for new process instances
- §9: process.exit for disappeared process instances
- §10: Compound process identity (pid, process_start_time) prevents PID reuse confusion
- §12: No premature truncation before lifecycle comparison
- §14: Recommended process fields including hash_status
- §15: command_line as array
- §16: UTC timestamps
- §17: Empty list means "nothing changed" not "no processes"
- §11: Collector reuse across cycles
"""

from unittest.mock import MagicMock, patch
import pytest

from collectors.process import ProcessCollector
from utils.hash import FileHasher


# ──────────────────────────────────────────────────────────────────────────────
# FileHasher Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_file_hasher_caching(tmp_path):
    """Verify FileHasher caches SHA-256 results to avoid repeated disk I/O."""
    hasher = FileHasher()
    test_file = tmp_path / "test_binary.exe"
    test_file.write_bytes(b"sysmon_test_payload_123")

    hash1 = hasher.calculate_hash(str(test_file))
    assert len(hash1) == 64
    assert hash1 in hasher._cache.values()

    # Second call retrieves from in-memory cache
    hash2 = hasher.calculate_hash(str(test_file))
    assert hash1 == hash2


def test_file_hasher_error_handling():
    """Verify FileHasher returns empty string for missing/inaccessible paths."""
    hasher = FileHasher()
    assert hasher.calculate_hash("") == ""
    assert hasher.calculate_hash("C:\\non_existent_path_99999.exe") == ""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_mock_proc(pid: int, ppid: int, name: str, create_time: float,
                    exe: str = "", cmdline: list = None, username: str = "user") -> MagicMock:
    """Create a mock psutil Process whose as_dict returns realistic process info."""
    mock = MagicMock()
    mock.as_dict.return_value = {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "cpu_percent": 1.0,
        "memory_percent": 2.0,
        "status": "running",
        "create_time": create_time,
        "exe": exe,
        "cmdline": cmdline or [name],
        "username": username,
        "cwd": "C:\\",
    }
    return mock


# ──────────────────────────────────────────────────────────────────────────────
# §7: Initial process.snapshot at startup
# ──────────────────────────────────────────────────────────────────────────────

def test_first_run_emits_process_snapshot():
    """§7: Agent startup should enumerate all processes and emit process.snapshot."""
    collector = ProcessCollector()

    proc_a = _make_mock_proc(1001, 1, "systemd", 1700000000.0, "/usr/lib/systemd/systemd")
    proc_b = _make_mock_proc(2002, 1001, "brave.exe", 1700000100.0,
                              "C:\\Program Files\\Brave\\brave.exe",
                              ["brave.exe", "--no-sandbox"])

    with patch("psutil.process_iter", return_value=[proc_a, proc_b]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        events = collector.collect_lifecycle_events()

    assert len(events) == 1
    snapshot = events[0]
    assert snapshot["event_type"] == "process.snapshot"
    assert "data" in snapshot
    assert len(snapshot["data"]["processes"]) == 2

    # Verify recommended fields (§14)
    brave = next(p for p in snapshot["data"]["processes"] if p["name"] == "brave.exe")
    assert brave["pid"] == 2002
    assert brave["ppid"] == 1001
    assert brave["command_line"] == ["brave.exe", "--no-sandbox"]  # §15: array
    assert brave["sha256"] == "a" * 64
    assert "hash_status" in brave  # §14
    assert "process_start_time" in brave  # §16
    assert brave["process_start_time"].endswith("Z")  # §16: UTC


# ──────────────────────────────────────────────────────────────────────────────
# §8: process.start for new processes
# ──────────────────────────────────────────────────────────────────────────────

def test_new_process_emits_process_start():
    """§8: A process appearing after the initial snapshot should emit process.start."""
    collector = ProcessCollector()

    proc_a = _make_mock_proc(1001, 1, "systemd", 1700000000.0, "/usr/lib/systemd/systemd")
    proc_b = _make_mock_proc(16924, 16872, "brave.exe", 1700000200.0,
                              "C:\\Program Files\\BraveSoftware\\brave.exe",
                              ["brave.exe", "--type=renderer"])

    with patch("psutil.process_iter", return_value=[proc_a]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        collector.collect_lifecycle_events()  # Initial snapshot

    with patch("psutil.process_iter", return_value=[proc_a, proc_b]), \
         patch.object(FileHasher, "calculate_hash", return_value="b" * 64):
        events = collector.collect_lifecycle_events()

    assert len(events) == 1
    start_event = events[0]
    assert start_event["event_type"] == "process.start"
    assert start_event["data"]["pid"] == 16924
    assert start_event["data"]["ppid"] == 16872
    assert start_event["data"]["name"] == "brave.exe"
    assert start_event["data"]["executable_path"] == "C:\\Program Files\\BraveSoftware\\brave.exe"
    assert start_event["data"]["command_line"] == ["brave.exe", "--type=renderer"]
    assert start_event["data"]["sha256"] == "b" * 64
    assert "process_start_time" in start_event["data"]


# ──────────────────────────────────────────────────────────────────────────────
# §9: process.exit for disappeared processes
# ──────────────────────────────────────────────────────────────────────────────

def test_exited_process_emits_process_exit():
    """§9: A process disappearing between scans should emit process.exit."""
    collector = ProcessCollector()

    proc_a = _make_mock_proc(1001, 1, "systemd", 1700000000.0, "/usr/lib/systemd/systemd")
    proc_b = _make_mock_proc(16924, 16872, "brave.exe", 1700000200.0,
                              "C:\\Program Files\\BraveSoftware\\brave.exe")

    with patch("psutil.process_iter", return_value=[proc_a, proc_b]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        collector.collect_lifecycle_events()  # Initial snapshot

    with patch("psutil.process_iter", return_value=[proc_a]):
        events = collector.collect_lifecycle_events()

    assert len(events) == 1
    exit_event = events[0]
    assert exit_event["event_type"] == "process.exit"
    assert exit_event["data"]["pid"] == 16924
    assert "process_start_time" in exit_event["data"]
    assert "observed_exit_time" in exit_event["data"]
    assert exit_event["data"]["observed_exit_time"].endswith("Z")


# ──────────────────────────────────────────────────────────────────────────────
# §17: Empty list means "nothing changed"
# ──────────────────────────────────────────────────────────────────────────────

def test_no_changes_returns_empty_list():
    """§17: A cycle with no process changes should return an empty list."""
    collector = ProcessCollector()

    proc_a = _make_mock_proc(1001, 1, "systemd", 1700000000.0, "/usr/lib/systemd/systemd")

    with patch("psutil.process_iter", return_value=[proc_a]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        collector.collect_lifecycle_events()  # Initial snapshot

    with patch("psutil.process_iter", return_value=[proc_a]):
        events = collector.collect_lifecycle_events()

    # Empty means "nothing changed", NOT "no processes running"
    assert events == []


# ──────────────────────────────────────────────────────────────────────────────
# §10: PID reuse detection via compound process identity
# ──────────────────────────────────────────────────────────────────────────────

def test_pid_reuse_creates_new_process_instance():
    """§10: A reused PID with a different process_start_time must be treated as a new process."""
    collector = ProcessCollector()

    original_proc = _make_mock_proc(5000, 1, "old_app.exe", 1700000000.0,
                                     "C:\\old_app.exe")

    with patch("psutil.process_iter", return_value=[original_proc]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        collector.collect_lifecycle_events()  # Initial snapshot

    # Same PID 5000, different create_time (PID reuse)
    reused_proc = _make_mock_proc(5000, 1, "new_app.exe", 1700009999.0,
                                   "C:\\new_app.exe")

    with patch("psutil.process_iter", return_value=[reused_proc]), \
         patch.object(FileHasher, "calculate_hash", return_value="b" * 64):
        events = collector.collect_lifecycle_events()

    # Should see both: exit of old_app.exe AND start of new_app.exe
    event_types = [e["event_type"] for e in events]
    assert "process.exit" in event_types
    assert "process.start" in event_types

    exit_event = next(e for e in events if e["event_type"] == "process.exit")
    assert exit_event["data"]["pid"] == 5000

    start_event = next(e for e in events if e["event_type"] == "process.start")
    assert start_event["data"]["pid"] == 5000
    assert start_event["data"]["name"] == "new_app.exe"


# ──────────────────────────────────────────────────────────────────────────────
# §11: Single collector instance across cycles
# ──────────────────────────────────────────────────────────────────────────────

def test_collector_maintains_state_across_cycles():
    """§11: A single ProcessCollector instance must maintain state across multiple cycles."""
    collector = ProcessCollector()

    proc_a = _make_mock_proc(1001, 1, "init", 1700000000.0, "/sbin/init")
    proc_b = _make_mock_proc(2002, 1001, "worker", 1700000100.0, "/usr/bin/worker")

    # Cycle 1: Snapshot
    with patch("psutil.process_iter", return_value=[proc_a]), \
         patch.object(FileHasher, "calculate_hash", return_value="a" * 64):
        events1 = collector.collect_lifecycle_events()
    assert len(events1) == 1
    assert events1[0]["event_type"] == "process.snapshot"

    # Cycle 2: New process starts
    with patch("psutil.process_iter", return_value=[proc_a, proc_b]), \
         patch.object(FileHasher, "calculate_hash", return_value="b" * 64):
        events2 = collector.collect_lifecycle_events()
    assert len(events2) == 1
    assert events2[0]["event_type"] == "process.start"
    assert events2[0]["data"]["name"] == "worker"

    # Cycle 3: No changes
    with patch("psutil.process_iter", return_value=[proc_a, proc_b]):
        events3 = collector.collect_lifecycle_events()
    assert events3 == []

    # Cycle 4: Process exits
    with patch("psutil.process_iter", return_value=[proc_a]):
        events4 = collector.collect_lifecycle_events()
    assert len(events4) == 1
    assert events4[0]["event_type"] == "process.exit"
    assert events4[0]["data"]["pid"] == 2002

    # Cycle 5: Still stable
    with patch("psutil.process_iter", return_value=[proc_a]):
        events5 = collector.collect_lifecycle_events()
    assert events5 == []


# ──────────────────────────────────────────────────────────────────────────────
# §14: Recommended process fields present
# ──────────────────────────────────────────────────────────────────────────────

def test_process_fields_completeness():
    """§14: All recommended fields must be present in process data."""
    collector = ProcessCollector()

    proc = _make_mock_proc(
        pid=1234, ppid=1, name="app.exe", create_time=1700000000.0,
        exe="C:\\app.exe", cmdline=["app.exe", "--flag"], username="DOMAIN\\user"
    )

    with patch("psutil.process_iter", return_value=[proc]), \
         patch.object(FileHasher, "calculate_hash", return_value="c" * 64):
        events = collector.collect_lifecycle_events()

    process_data = events[0]["data"]["processes"][0]

    required_fields = [
        "pid", "ppid", "process_start_time", "name", "executable_path",
        "command_line", "username", "sha256", "hash_status", "working_directory",
    ]
    for field in required_fields:
        assert field in process_data, f"Missing required field: {field}"
