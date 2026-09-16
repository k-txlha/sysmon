"""
agent/utils/buffer.py

Local Bounded Disk Buffer for the Sysmon Agent.
Provides durable FIFO queuing using SQLite to ensure telemetry and security events
are never lost during network partitions, backend outages, or rate-limiting.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import setup_logger

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
    ) -> None:
        self.db_path = db_path
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0,
                isolation_level=None,  # Autocommit mode
            )
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
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
                logger.error(f"Database corruption detected ({e}). Resetting local buffer...")
                self._recover_corrupt_db()

    def _recover_corrupt_db(self) -> None:
        """Handles corrupt database file by backing it up and starting fresh."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

        if os.path.exists(self.db_path):
            corrupt_backup = f"{self.db_path}.corrupt.{int(time.time())}"
            try:
                os.rename(self.db_path, corrupt_backup)
                logger.warning(f"Moved corrupted buffer to {corrupt_backup}")
            except OSError as err:
                logger.error(f"Failed to rename corrupt database: {err}")

        # Re-initialize clean connection
        self._init_db()

    def push(self, event_data: Dict[str, Any]) -> bool:
        """
        Enqueues an event envelope dictionary to the disk buffer.
        Evicts oldest items if capacity or byte limit is exceeded.
        """
        if not event_data:
            return False

        event_id = event_data.get("event_id", "")
        event_type = event_data.get("event_type", "unknown")
        payload_str = json.dumps(event_data, default=str)
        now_ts = time.time()

        with self._lock:
            try:
                conn = self._get_connection()

                # Check and enforce capacity limits
                self._enforce_capacity(conn)

                conn.execute(
                    """
                    INSERT OR REPLACE INTO pending_events (event_id, event_type, payload_json, created_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (event_id, event_type, payload_str, now_ts),
                )
                return True
            except sqlite3.DatabaseError as e:
                logger.error(f"Failed to push event to buffer: {e}")
                self._recover_corrupt_db()
                return False

    def _enforce_capacity(self, conn: sqlite3.Connection) -> None:
        """Evicts oldest events if count or disk space limits are exceeded."""
        cursor = conn.execute("SELECT COUNT(*) FROM pending_events;")
        row = cursor.fetchone()
        current_count = row[0] if row else 0

        evict_count = 0
        if current_count >= self.max_events:
            evict_count = max(current_count - self.max_events + 10, 10)

        # Also check file size limit
        file_size = self.get_buffer_size_bytes()
        if file_size >= self.max_bytes:
            evict_count = max(evict_count, 100)

        if evict_count > 0:
            conn.execute(
                """
                DELETE FROM pending_events
                WHERE id IN (
                    SELECT id FROM pending_events ORDER BY id ASC LIMIT ?
                );
                """,
                (evict_count,),
            )
            conn.execute(
                """
                UPDATE buffer_stats
                SET stat_value = stat_value + ?
                WHERE stat_key = 'dropped_events_total';
                """,
                (evict_count,),
            )
            logger.warning(
                f"Buffer capacity exceeded. Evicted {evict_count} oldest events to prevent overflow."
            )

    def peek_batch(self, batch_size: int = 50) -> List[Tuple[int, Dict[str, Any]]]:
        """
        Retrieves up to `batch_size` pending events in FIFO order without removing them.
        Returns a list of (row_id, event_dict) tuples.
        """
        with self._lock:
            try:
                conn = self._get_connection()
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
                        results.append((row_id, json.loads(payload_json)))
                    except json.JSONDecodeError:
                        # Malformed entry, delete it immediately
                        conn.execute("DELETE FROM pending_events WHERE id = ?;", (row_id,))
                return results
            except sqlite3.DatabaseError as e:
                logger.error(f"Failed to read from buffer: {e}")
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
            except sqlite3.DatabaseError:
                return 0

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
            except sqlite3.DatabaseError:
                return 0

    def get_buffer_size_bytes(self) -> int:
        """Returns the file size of the buffer database on disk."""
        try:
            if os.path.exists(self.db_path):
                return os.path.getsize(self.db_path)
        except OSError:
            pass
        return 0

    def close(self) -> None:
        """Closes the database connection cleanly."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
