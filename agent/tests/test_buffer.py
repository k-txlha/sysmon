"""
Tests for Agent LocalBoundedBuffer (Offline Queuing & Resilience).
"""

import json
import os
import stat
import tempfile
import time
import pytest

from agent.utils.buffer import LocalBoundedBuffer


@pytest.fixture
def temp_buffer():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_buffer.db")
        buffer = LocalBoundedBuffer(db_path=db_path, max_events=10, max_bytes=1024 * 1024)
        yield buffer
        buffer.close()


def test_push_and_peek(temp_buffer):
    event = {
        "event_id": "evt-001",
        "event_type": "telemetry.snapshot",
        "data": {"foo": "bar"},
    }
    assert temp_buffer.push(event) is True
    assert temp_buffer.get_depth() == 1

    batch = temp_buffer.peek_batch(batch_size=10)
    assert len(batch) == 1
    row_id, item = batch[0]
    assert item["event_id"] == "evt-001"
    assert item["data"]["foo"] == "bar"


def test_pop_batch_removes_items(temp_buffer):
    for i in range(5):
        temp_buffer.push({"event_id": f"evt-{i}", "event_type": "test"})

    assert temp_buffer.get_depth() == 5

    batch = temp_buffer.peek_batch(batch_size=3)
    assert len(batch) == 3
    row_ids = [item[0] for item in batch]

    popped = temp_buffer.pop_batch(row_ids)
    assert popped == 3
    assert temp_buffer.get_depth() == 2


def test_fifo_ordering(temp_buffer):
    for i in range(4):
        temp_buffer.push({"event_id": f"evt-{i}", "order": i})

    batch = temp_buffer.peek_batch(batch_size=10)
    orders = [item[1]["order"] for item in batch]
    assert orders == [0, 1, 2, 3]


def test_capacity_eviction_and_dropped_counter(temp_buffer):
    # Buffer has max_events=10
    for i in range(15):
        temp_buffer.push({"event_id": f"evt-{i}", "seq": i})

    # Should not exceed capacity, should evict oldest
    assert temp_buffer.get_depth() <= 10
    assert temp_buffer.get_dropped_count() > 0
    queued = [event["seq"] for _, event in temp_buffer.peek_batch(batch_size=20)]
    assert queued == list(range(5, 15))


def test_duplicate_event_id_is_idempotent(temp_buffer):
    assert temp_buffer.push({"event_id": "same-id", "value": "original"})
    assert temp_buffer.push({"event_id": "same-id", "value": "replacement"})
    batch = temp_buffer.peek_batch()
    assert len(batch) == 1
    assert batch[0][1]["value"] == "original"


def test_buffer_persists_across_restart(tmp_path):
    db_path = str(tmp_path / "restart.db")
    first = LocalBoundedBuffer(db_path=db_path)
    assert first.push({"event_id": "persisted"})
    first.close()

    second = LocalBoundedBuffer(db_path=db_path)
    try:
        assert [event["event_id"] for _, event in second.peek_batch()] == ["persisted"]
    finally:
        second.close()


def test_legacy_pending_event_receives_stable_id_before_delivery(tmp_path):
    buffer = LocalBoundedBuffer(db_path=str(tmp_path / "legacy.db"))
    try:
        buffer._get_connection().execute(
            """
            INSERT INTO pending_events (event_id, event_type, payload_json, created_at)
            VALUES ('', 'legacy', ?, ?)
            """,
            (json.dumps({"event_type": "legacy"}), time.time()),
        )
        queued_id, event = buffer.peek_batch()[0]
        assert event["event_id"]
        row = buffer._get_connection().execute(
            "SELECT event_id FROM pending_events WHERE id = ?", (queued_id,)
        ).fetchone()
        assert row[0] == event["event_id"]
    finally:
        buffer.close()


def test_byte_capacity_rejects_an_oversized_event(tmp_path):
    buffer = LocalBoundedBuffer(
        db_path=str(tmp_path / "small.db"),
        max_events=10,
        max_bytes=80,
    )
    try:
        assert not buffer.push({"event_id": "too-large", "value": "x" * 200})
        assert buffer.get_depth() == 0
        assert buffer.get_dropped_count() == 1
    finally:
        buffer.close()


def test_retention_expires_events_with_a_warning_count(temp_buffer):
    temp_buffer.retention_seconds = 1
    assert temp_buffer.push({"event_id": "expired"})
    with temp_buffer._lock:
        temp_buffer._get_connection().execute(
            "UPDATE pending_events SET created_at = ?", (time.time() - 10,)
        )
    assert temp_buffer.peek_batch() == []
    assert temp_buffer.get_dropped_count() == 1


def test_buffer_database_has_owner_only_permissions(temp_buffer):
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(temp_buffer.db_path).st_mode)
        assert mode == 0o600


def test_corruption_recovery():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "corrupt_test.db")
        # Write garbage to simulate disk corruption
        with open(db_path, "w") as f:
            f.write("GARBAGE DATA THAT IS NOT SQLITE")

        buffer = LocalBoundedBuffer(db_path=db_path)
        # Should cleanly recover by resetting
        assert buffer.push({"event_id": "evt-recovery", "event_type": "test"}) is True
        assert buffer.get_depth() == 1
        buffer.close()
