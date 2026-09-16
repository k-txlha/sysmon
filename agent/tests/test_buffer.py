"""
Tests for Agent LocalBoundedBuffer (Offline Queuing & Resilience).
"""

import os
import tempfile
import pytest

from utils.buffer import LocalBoundedBuffer


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
