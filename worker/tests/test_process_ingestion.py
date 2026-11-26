import datetime
from unittest.mock import MagicMock

from worker.db.ch_client import ClickHouseService
from worker.main import _extract_process_rows


def test_init_db_creates_process_events_table():
    service = ClickHouseService()
    service.client = MagicMock()

    service.init_db()

    commands = [call.args[0] for call in service.client.command.call_args_list]
    assert any("CREATE TABLE IF NOT EXISTS PROCESS_EVENTS" in cmd for cmd in commands)


def test_insert_process_events_batch_inserts_expected_columns():
    service = ClickHouseService()
    service.client = MagicMock()
    ts = datetime.datetime(2026, 11, 26, 11, 50, 0)
    rows = [
        (
            "agent-linux-1",
            "default",
            "ubuntu-host",
            "evt-1",
            "process.start",
            ts,
            1234,
            1,
            "sshd",
            "/usr/sbin/sshd",
            ["/usr/sbin/sshd", "-D"],
            "2026-11-26T11:49:55Z",
            "",
            "abc123",
            "success",
            "root",
            "/",
        )
    ]

    service.insert_process_events_batch(rows)

    service.client.insert.assert_called_once()
    table_name, inserted_rows = service.client.insert.call_args.args[:2]
    assert table_name.endswith(".PROCESS_EVENTS")
    assert inserted_rows == rows
    assert service.client.insert.call_args.kwargs["column_names"] == [
        "agent_id",
        "tenant_id",
        "host_id",
        "event_id",
        "event_type",
        "timestamp",
        "pid",
        "ppid",
        "name",
        "executable_path",
        "command_line",
        "process_start_time",
        "observed_exit_time",
        "sha256",
        "hash_status",
        "username",
        "working_directory",
    ]


def test_extract_process_rows_handles_snapshot_with_linux_kernel_threads():
    ts = datetime.datetime(2026, 11, 26, 11, 50, 0)
    payload = {
        "agent_id": "agent-linux-1",
        "tenant_id": "default",
        "host_id": "ubuntu-host",
        "event_id": "evt-snap-1",
        "event_type": "process.snapshot",
        "data": {
            "processes": [
                {
                    "pid": 2,
                    "ppid": 0,
                    "name": "kthreadd",
                    "executable_path": "",
                    "command_line": [],
                    "process_start_time": "2026-11-26T00:00:00Z",
                    "sha256": "",
                    "hash_status": "no_executable",
                    "username": None,
                    "working_directory": None,
                },
                {
                    "pid": 1024,
                    "ppid": 1,
                    "name": "python3",
                    "executable_path": "/usr/bin/python3",
                    "command_line": ["/usr/bin/python3", "-m", "agent.main"],
                    "process_start_time": "2026-11-26T11:00:00Z",
                    "sha256": "deadbeef",
                    "hash_status": "success",
                    "username": "root",
                    "working_directory": "/opt/sysmon",
                },
            ]
        },
    }

    rows = _extract_process_rows(payload, ts)
    assert len(rows) == 2
    assert rows[0][4] == "process.snapshot"
    assert rows[0][6] == 2
    assert rows[0][15] == ""  # username None normalized to ""
    assert rows[0][16] == ""  # working_directory None normalized to ""
    assert rows[1][8] == "python3"
    assert rows[1][10] == ["/usr/bin/python3", "-m", "agent.main"]


def test_extract_process_rows_handles_start_and_exit():
    ts = datetime.datetime(2026, 11, 26, 11, 50, 5)
    start_payload = {
        "agent_id": "agent-linux-1",
        "tenant_id": "default",
        "host_id": "ubuntu-host",
        "event_id": "evt-start-1",
        "event_type": "process.start",
        "data": {
            "pid": 4321,
            "ppid": 1024,
            "name": "bash",
            "executable_path": "/usr/bin/bash",
            "command_line": ["/usr/bin/bash"],
            "process_start_time": "2026-11-26T11:50:04Z",
            "sha256": "cafebabe",
            "hash_status": "success",
            "username": "talha",
            "working_directory": "/home/talha",
        },
    }
    exit_payload = {
        "agent_id": "agent-linux-1",
        "tenant_id": "default",
        "host_id": "ubuntu-host",
        "event_id": "evt-exit-1",
        "event_type": "process.exit",
        "data": {
            "pid": 4321,
            "process_start_time": "2026-11-26T11:50:04Z",
            "observed_exit_time": "2026-11-26T11:50:05Z",
        },
    }

    start_rows = _extract_process_rows(start_payload, ts)
    exit_rows = _extract_process_rows(exit_payload, ts)

    assert len(start_rows) == 1
    assert start_rows[0][4] == "process.start"
    assert start_rows[0][6] == 4321
    assert start_rows[0][12] == ""

    assert len(exit_rows) == 1
    assert exit_rows[0][4] == "process.exit"
    assert exit_rows[0][6] == 4321
    assert exit_rows[0][12] == "2026-11-26T11:50:05Z"
