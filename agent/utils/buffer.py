"""
agent/utils/buffer.py

Local Bounded Disk Buffer for the Sysmon Agent.
Provides durable FIFO queuing using SQLite during network partitions and outages,
with explicit retention and overflow policies.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from agent.utils.logger import setup_logger

logger = setup_logger("agent_buffer")


class LocalBoundedBuffer:
    """
    Thread-safe, crash-resilient SQLite-backed FIFO event buffer.

    Enforces strict disk quotas and item limits with FIFO eviction.
    """

    def __init__(
        self,
        db_path: str = ".agent_buffer.db",
        max_events: int = 25000,
        max_bytes: int = 50 * 1024 * 1024,  # 50 MB
        retention_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        if max_events < 1 or max_bytes < 1 or retention_seconds < 1:
            raise ValueError("Buffer limits and retention must be greater than zero.")
        self.db_path = db_path
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.retention_seconds = retention_seconds
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._secured_files: set[str] = set()
        self._init_db()

    def _secure_files(self) -> None:
        for path in (self.db_path, f"{self.db_path}-wal", f"{self.db_path}-shm"):
            if path in self._secured_files or not os.path.exists(path):
                continue
            if os.name == "nt":
                identity = subprocess.run(
                    ["whoami"], check=True, capture_output=True, text=True
                ).stdout.strip()
                subprocess.run(
                    [
                        "icacls",
                        path,
                        "/inheritance:r",
                        "/grant:r",
                        f"{identity}:(F)",
                        "SYSTEM:(F)",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            else:
                os.chmod(path, 0o600)
            self._secured_files.add(path)

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            if os.name != "nt":
                descriptor = os.open(
                    self.db_path, os.O_CREAT | os.O_RDWR, 0o600
                )
                os.close(descriptor)
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0,
                isolation_level=None,  # Autocommit mode
            )
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = FULL;")
            page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
            max_db_bytes = self.max_bytes + self.max_events * 256 + 1024 * 1024
            self._conn.execute(
                f"PRAGMA max_page_count = {max(1, math.ceil(max_db_bytes / page_size))}"
            )
            self._secure_files()
        return self._conn

    def _init_db(self) -> None:
        """Initializes database schema with corruption recovery."""
        with self._lock:
            try:
                conn = self._get_connection()
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pending_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE,
                        event_type TEXT,
                        payload_json TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS buffer_stats (
                        stat_key TEXT PRIMARY KEY,
                        stat_value INTEGER NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO buffer_stats (stat_key, stat_value)
                    VALUES ('dropped_events_total', 0);
                    """
                )
            except sqlite3.DatabaseError as e:
                if self._is_corruption_error(e):
                    logger.error(
                        "Database corruption detected (%s); preserving the damaged "
                        "buffer for recovery and creating a fresh queue.",
                        e,
                    )
                    self._recover_corrupt_db()
                else:
                    raise

    @staticmethod
    def _is_corruption_error(error: sqlite3.DatabaseError) -> bool:
        message = str(error).lower()
        return "not a database" in message or "malformed" in message

    def _recover_corrupt_db(self) -> None:
        """Handles corrupt database file by backing it up and starting fresh."""
        if self._conn:
            try:
                self._conn.close()
            except sqlite3.DatabaseError as err:
                logger.error("Failed to close corrupted buffer connection: %s", err)
            self._conn = None

        if os.path.exists(self.db_path):
            corrupt_backup = f"{self.db_path}.corrupt.{int(time.time())}"
            preservation_error: Optional[OSError] = None
            for path in (self.db_path, f"{self.db_path}-wal", f"{self.db_path}-shm"):
                if os.path.exists(path):
                    suffix = path[len(self.db_path) :]
                    try:
                        os.rename(path, f"{corrupt_backup}{suffix}")
                    except OSError as err:
                        logger.error("Failed to preserve corrupted buffer file: %s", err)
                        preservation_error = err
            if preservation_error:
                raise RuntimeError(
                    "Unable to preserve corrupted agent buffer files."
                ) from preservation_error
            logger.warning("Preserved corrupted buffer files at %s.", corrupt_backup)

        self._secured_files.clear()
        # Re-initialize clean connection
        self._init_db()

    def push(self, event_data: Dict[str, Any]) -> bool:
        """
        Enqueues an event envelope dictionary to the disk buffer.
        Evicts oldest unacknowledged items on capacity overflow.
        """
        if not event_data:
            return False

        event = dict(event_data)
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            event_id = str(uuid.uuid4())
            event["event_id"] = event_id
        event_type = event.get("event_type", "unknown")
        payload_str = json.dumps(event, default=str, separators=(",", ":"))
        payload_size = len(payload_str.encode("utf-8"))
        now_ts = time.time()

        with self._lock:
            try:
                conn = self._get_connection()
                existing = conn.execute(
                    "SELECT 1 FROM pending_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if existing:
                    return True

                self._expire_retained(conn, now_ts)
                if payload_size > self.max_bytes:
                    self._record_dropped(conn, 1)
                    logger.warning(
                        "Buffer overflow policy dropped an event larger than the "
                        "configured byte capacity (%s > %s bytes).",
                        payload_size,
                        self.max_bytes,
                    )
                    return False
                self._make_room(conn, payload_size)

                conn.execute(
                    """
                    INSERT OR IGNORE INTO pending_events
                        (event_id, event_type, payload_json, created_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (event_id, event_type, payload_str, now_ts),
                )
                self._secure_files()
                return True
            except sqlite3.DatabaseError as e:
                logger.error(f"Failed to push event to buffer: {e}")
                if self._is_corruption_error(e):
                    self._recover_corrupt_db()
                return False

    @staticmethod
    def _record_dropped(conn: sqlite3.Connection, count: int) -> None:
        conn.execute(
            """
            UPDATE buffer_stats
            SET stat_value = stat_value + ?
            WHERE stat_key = 'dropped_events_total';
            """,
            (count,),
        )

    def _expire_retained(self, conn: sqlite3.Connection, now_ts: float) -> None:
        cursor = conn.execute(
            "DELETE FROM pending_events WHERE created_at < ?",
            (now_ts - self.retention_seconds,),
        )
        expired = cursor.rowcount
        if expired:
            self._record_dropped(conn, expired)
            logger.warning(
                "Buffer retention policy expired %s unacknowledged event(s) older "
                "than %s seconds.",
                expired,
                self.retention_seconds,
            )

    def _make_room(self, conn: sqlite3.Connection, payload_size: int) -> None:
        """Apply the documented drop-oldest policy until the new event fits."""
        count, used_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(length(payload_json)), 0) FROM pending_events"
        ).fetchone()
        evicted_ids = []
        while count >= self.max_events or used_bytes + payload_size > self.max_bytes:
            oldest = conn.execute(
                "SELECT id, length(payload_json) FROM pending_events ORDER BY id LIMIT 1"
            ).fetchone()
            if oldest is None:
                break
            evicted_ids.append(oldest[0])
            count -= 1
            used_bytes -= oldest[1]

        if evicted_ids:
            placeholders = ",".join("?" for _ in evicted_ids)
            conn.execute(
                f"DELETE FROM pending_events WHERE id IN ({placeholders})",
                evicted_ids,
            )
            self._record_dropped(conn, len(evicted_ids))
            logger.warning(
                "Buffer capacity reached; overflow policy evicted %s oldest "
                "unacknowledged event(s) (drop-oldest).",
                len(evicted_ids),
            )

    def peek_batch(self, batch_size: int = 50) -> List[Tuple[int, Dict[str, Any]]]:
        """
        Retrieves up to `batch_size` pending events in FIFO order without removing them.
        Returns a list of (row_id, event_dict) tuples.
        """
        with self._lock:
            try:
                conn = self._get_connection()
                self._expire_retained(conn, time.time())
                cursor = conn.execute(
                    """
                    SELECT id, payload_json FROM pending_events
                    ORDER BY id ASC LIMIT ?;
                    """,
                    (batch_size,),
                )
                results: List[Tuple[int, Dict[str, Any]]] = []
                for row_id, payload_json in cursor.fetchall():
                    try:
                        event = json.loads(payload_json)
                    except json.JSONDecodeError:
                        logger.error(
                            "Pending buffer event %s is malformed; retaining it for "
                            "manual recovery instead of deleting it.",
                            row_id,
                        )
                        return []
                    if not isinstance(event, dict):
                        logger.error(
                            "Pending buffer event %s is not an event object; retaining "
                            "it for manual recovery.",
                            row_id,
                        )
                        return []
                    event_id = event.get("event_id")
                    if not isinstance(event_id, str) or not event_id:
                        event_id = str(uuid.uuid4())
                        event["event_id"] = event_id
                        updated_payload = json.dumps(
                            event, default=str, separators=(",", ":")
                        )
                        conn.execute(
                            """
                            UPDATE pending_events
                            SET event_id = ?, payload_json = ?
                            WHERE id = ?
                            """,
                            (event_id, updated_payload, row_id),
                        )
                    results.append((row_id, event))
                self._secure_files()
                return results
            except sqlite3.DatabaseError as e:
                logger.error(f"Failed to read from buffer: {e}")
                if self._is_corruption_error(e):
                    self._recover_corrupt_db()
                return []

    def pop_batch(self, row_ids: List[int]) -> int:
        """
        Permanently removes successfully acknowledged events from the buffer by row ID.
        """
        if not row_ids:
            return 0

        with self._lock:
            try:
                conn = self._get_connection()
                placeholders = ",".join("?" for _ in row_ids)
                cursor = conn.execute(
                    f"DELETE FROM pending_events WHERE id IN ({placeholders});",
                    row_ids,
                )
                return cursor.rowcount
            except sqlite3.DatabaseError as e:
                logger.error(f"Failed to delete acknowledged events: {e}")
                return 0

    def get_depth(self) -> int:
        """Returns the number of pending events in the queue."""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.execute("SELECT COUNT(*) FROM pending_events;")
                row = cursor.fetchone()
                return row[0] if row else 0
            except sqlite3.DatabaseError as exc:
                logger.error("Failed to count buffered events: %s", exc)
                raise RuntimeError("Unable to count pending buffer events.") from exc

    def get_dropped_count(self) -> int:
        """Returns the total number of events dropped due to buffer capacity."""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.execute(
                    "SELECT stat_value FROM buffer_stats WHERE stat_key = 'dropped_events_total';"
                )
                row = cursor.fetchone()
                return row[0] if row else 0
            except sqlite3.DatabaseError as exc:
                logger.error("Failed to read buffer drop counter: %s", exc)
                raise RuntimeError("Unable to read the buffer drop counter.") from exc

    def get_buffer_size_bytes(self) -> int:
        """Returns the file size of the buffer database on disk."""
        try:
            return sum(
                os.path.getsize(path)
                for path in (
                    self.db_path,
                    f"{self.db_path}-wal",
                    f"{self.db_path}-shm",
                )
                if os.path.exists(path)
            )
        except OSError as exc:
            logger.exception("Failed to determine local buffer disk usage.")
            raise RuntimeError("Unable to determine local buffer disk usage.") from exc

    def close(self) -> None:
        """Closes the database connection cleanly."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except sqlite3.DatabaseError as exc:
                    logger.error("Failed to close local agent buffer: %s", exc)
                    raise
                else:
                    self._conn = None
