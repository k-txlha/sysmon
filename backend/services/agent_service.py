"""SQLite-backed agent enrollment, credential, and heartbeat service."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

from backend.config.settings import settings

_IN_MEMORY_HEARTBEATS: Dict[str, float] = {}
BOOTSTRAP_TOKEN_TTL = timedelta(minutes=30)
AGENT_TOKEN_TTL = timedelta(hours=1)
TOKEN_RENEWAL_WINDOW = timedelta(minutes=5)
TOKEN_ROTATION_OVERLAP = timedelta(minutes=10)


class AgentService:
    def __init__(self) -> None:
        self._token_lock = asyncio.Lock()
        self._initialized_path: Optional[str] = None

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        from backend.services.auth_service import auth_service

        auth_service.initialize()
        path = str(auth_service.database_path.resolve())
        if self._initialized_path != path:
            connection = sqlite3.connect(path, timeout=10)
            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        operating_system TEXT NOT NULL,
                        mac_address TEXT NOT NULL,
                        machine_architecture TEXT NOT NULL,
                        enrolled_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        current_token_hash TEXT
                    );
                    CREATE TABLE IF NOT EXISTS agent_credentials (
                        id TEXT PRIMARY KEY,
                        agent_id TEXT REFERENCES agents(agent_id),
                        tenant_id TEXT,
                        token_hash TEXT NOT NULL UNIQUE,
                        token_type TEXT NOT NULL CHECK (token_type IN ('bootstrap', 'agent')),
                        description TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        revoked_at TEXT,
                        last_used_at TEXT,
                        superseded_by_hash TEXT,
                        rotation_recovery_until TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent
                        ON agent_credentials(agent_id);
                    CREATE INDEX IF NOT EXISTS idx_agent_credentials_expiration
                        ON agent_credentials(expires_at);
                    CREATE TABLE IF NOT EXISTS telemetry_receipts (
                        agent_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        accepted_at TEXT NOT NULL,
                        PRIMARY KEY (agent_id, event_id)
                    );
                    """
                )
                agent_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(agents)")
                }
                if "current_token_hash" not in agent_columns:
                    connection.execute(
                        "ALTER TABLE agents ADD COLUMN current_token_hash TEXT"
                    )
            finally:
                connection.close()
            self._initialized_path = path

        connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def telemetry_receipt_transaction(
        self, agent_id: str, event_ids: List[str]
    ) -> Generator[Tuple[set[str], sqlite3.Connection], None, None]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                placeholders = ",".join("?" for _ in event_ids)
                rows = (
                    connection.execute(
                        f"""
                        SELECT event_id FROM telemetry_receipts
                        WHERE agent_id = ? AND event_id IN ({placeholders})
                        """,
                        [agent_id, *event_ids],
                    ).fetchall()
                    if event_ids
                    else []
                )
                yield {row["event_id"] for row in rows}, connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def record_accepted_events(
        self,
        agent_id: str,
        event_ids: List[str],
        connection: Optional[sqlite3.Connection] = None,
    ) -> None:
        if not event_ids:
            return
        accepted_at = self._as_iso(self._utc_now())
        entries = [(agent_id, event_id, accepted_at) for event_id in event_ids]
        if connection is not None:
            connection.executemany(
                """
                INSERT OR IGNORE INTO telemetry_receipts
                    (agent_id, event_id, accepted_at)
                VALUES (?, ?, ?)
                """,
                entries,
            )
            return
        with self._connect() as own_connection:
            own_connection.execute("BEGIN IMMEDIATE")
            own_connection.executemany(
                """
                INSERT OR IGNORE INTO telemetry_receipts
                    (agent_id, event_id, accepted_at)
                VALUES (?, ?, ?)
                """,
                entries,
            )
            own_connection.commit()

    @staticmethod
    def _token_key(token_str: str) -> str:
        return hashlib.sha256(token_str.encode("utf-8")).hexdigest()

    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _as_iso(value: datetime) -> str:
        return value.isoformat(timespec="microseconds")

    @classmethod
    def _credential_data(cls, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["expiration"] = data.pop("expires_at")
        data["revoked"] = data["revoked_at"] is not None
        data["token_id"] = data["id"]
        return data

    async def generate_token(
        self, description: str = "Default Agent Token"
    ) -> Dict[str, Any]:
        """Create a short-lived, single-use bootstrap token."""
        token = f"sysmon_tok_{secrets.token_urlsafe(32)}"
        now = self._utc_now()
        token_hash = self._token_key(token)
        token_id = str(uuid.uuid4())
        expires_at = self._as_iso(now + BOOTSTRAP_TOKEN_TTL)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_credentials
                    (id, token_hash, token_type, description, created_at, expires_at)
                VALUES (?, ?, 'bootstrap', ?, ?, ?)
                """,
                (token_id, token_hash, description, self._as_iso(now), expires_at),
            )
        return {
            "token_id": token_id,
            "token": token,
            "description": description,
            "created_at": self._as_iso(now),
            "last_used_at": None,
            "expiration": expires_at,
            "token_type": "bootstrap",
            "revoked": False,
        }

    def _load_token_by_key(self, token_key: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_credentials WHERE token_hash = ?", (token_key,)
            ).fetchone()
        return self._credential_data(row) if row else None

    def _load_token(self, token: str) -> Optional[Dict[str, Any]]:
        return self._load_token_by_key(self._token_key(token))

    def _load_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _expiration(token_data: Dict[str, Any]) -> Optional[datetime]:
        expiration = token_data.get("expiration")
        if not expiration:
            return None
        parsed = datetime.fromisoformat(expiration)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

    def _active_credential(
        self, connection: sqlite3.Connection, token_hash: str, now: datetime
    ) -> Optional[Dict[str, Any]]:
        row = connection.execute(
            "SELECT * FROM agent_credentials WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not row or row["revoked_at"] is not None:
            return None
        data = self._credential_data(row)
        expiration = self._expiration(data)
        if expiration is not None and expiration <= now:
            return None
        if row["agent_id"]:
            agent = connection.execute(
                "SELECT status FROM agents WHERE agent_id = ?", (row["agent_id"],)
            ).fetchone()
            if not agent or agent["status"] != "active":
                return None
            current_hash = connection.execute(
                "SELECT current_token_hash FROM agents WHERE agent_id = ?",
                (row["agent_id"],),
            ).fetchone()
            if not current_hash:
                return None
            is_current = current_hash["current_token_hash"] == token_hash
            is_overlap = (
                row["superseded_by_hash"] == current_hash["current_token_hash"]
                and data.get("rotation_recovery_until")
                and datetime.fromisoformat(data["rotation_recovery_until"]) > now
            )
            if not is_current and not is_overlap:
                return None
        return data

    async def enroll_agent(
        self,
        bootstrap_token: str,
        hostname: str,
        operating_system: str,
        mac_address: str,
        machine_architecture: str = "x86_64",
        tenant_id: str = "default",
    ) -> Optional[Dict[str, Any]]:
        """Consume a bootstrap token and create a server-identified agent."""
        del tenant_id
        now = self._utc_now()
        now_iso = self._as_iso(now)
        bootstrap_hash = self._token_key(bootstrap_token)
        agent_id = f"agent_{uuid.uuid4().hex}"
        trusted_tenant_id = settings.DEFAULT_TENANT_ID
        token = f"sysmon_agent_{secrets.token_urlsafe(32)}"
        token_hash = self._token_key(token)
        expiration = self._as_iso(now + AGENT_TOKEN_TTL)
        token_id = str(uuid.uuid4())

        async with self._token_lock:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                bootstrap = connection.execute(
                    "SELECT * FROM agent_credentials WHERE token_hash = ?",
                    (bootstrap_hash,),
                ).fetchone()
                if (
                    not bootstrap
                    or bootstrap["token_type"] != "bootstrap"
                    or bootstrap["revoked_at"] is not None
                    or datetime.fromisoformat(bootstrap["expires_at"]) <= now
                ):
                    connection.rollback()
                    return None
                connection.execute(
                    """
                    INSERT INTO agents
                        (agent_id, tenant_id, hostname, operating_system, mac_address,
                         machine_architecture, enrolled_at, status, current_token_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        agent_id,
                        trusted_tenant_id,
                        hostname,
                        operating_system,
                        mac_address,
                        machine_architecture,
                        now_iso,
                        token_hash,
                    ),
                )
                connection.execute(
                    """
                    UPDATE agent_credentials
                    SET revoked_at = ?, last_used_at = ?
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (now_iso, now_iso, bootstrap["id"]),
                )
                connection.execute(
                    """
                    INSERT INTO agent_credentials
                        (id, agent_id, tenant_id, token_hash, token_type, description,
                         created_at, expires_at, last_used_at)
                    VALUES (?, ?, ?, ?, 'agent', ?, ?, ?, ?)
                    """,
                    (
                        token_id,
                        agent_id,
                        trusted_tenant_id,
                        token_hash,
                        f"Enrolled Agent: {hostname}",
                        now_iso,
                        expiration,
                        now_iso,
                    ),
                )
                connection.commit()

        enrollment = {
            "agent_id": agent_id,
            "tenant_id": trusted_tenant_id,
            "hostname": hostname,
            "operating_system": operating_system,
            "mac_address": mac_address,
            "machine_architecture": machine_architecture,
            "current_token_hash": token_hash,
            "enrolled_at": now_iso,
            "status": "active",
            "expires_at": expiration,
        }
        return {**enrollment, "agent_token": token}

    async def renew_token(self, token_str: str) -> Optional[Dict[str, Any]]:
        """Rotate an expiring credential, retaining bounded recovery overlap."""
        now = self._utc_now()
        token_hash = self._token_key(token_str)
        replacement = f"sysmon_agent_{secrets.token_urlsafe(32)}"
        replacement_hash = self._token_key(replacement)
        replacement_id = str(uuid.uuid4())
        now_iso = self._as_iso(now)
        new_expiration = self._as_iso(now + AGENT_TOKEN_TTL)

        async with self._token_lock:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                token = self._active_credential(connection, token_hash, now)
                if not token or token.get("token_type") != "agent":
                    connection.rollback()
                    return None
                agent_id = token["agent_id"]
                agent = connection.execute(
                    "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
                ).fetchone()
                if not agent or agent["status"] != "active":
                    connection.rollback()
                    return None
                connection.execute(
                    "UPDATE agent_credentials SET last_used_at = ? WHERE token_hash = ?",
                    (now_iso, token_hash),
                )
                current_hash = agent["current_token_hash"]
                expires = self._expiration(token)
                if (
                    current_hash == token_hash
                    and expires is not None
                    and expires > now + TOKEN_RENEWAL_WINDOW
                ):
                    token["token"] = token_str
                    token["renewed"] = False
                    connection.commit()
                    return token

                if current_hash == token_hash:
                    recovery_until = max(
                        expires or now,
                        now + TOKEN_ROTATION_OVERLAP,
                    )
                else:
                    if token.get("superseded_by_hash") != current_hash:
                        connection.rollback()
                        return None
                    recovery_value = token.get("rotation_recovery_until")
                    if not recovery_value:
                        connection.rollback()
                        return None
                    recovery_until = datetime.fromisoformat(recovery_value)
                    if recovery_until <= now:
                        connection.rollback()
                        return None

                recovery_iso = self._as_iso(recovery_until)
                connection.execute(
                    """
                    UPDATE agent_credentials
                    SET expires_at = ?, superseded_by_hash = ?,
                        rotation_recovery_until = ?
                    WHERE token_hash = ?
                    """,
                    (recovery_iso, replacement_hash, recovery_iso, token_hash),
                )
                connection.execute(
                    """
                    INSERT INTO agent_credentials
                        (id, agent_id, tenant_id, token_hash, token_type, description,
                         created_at, expires_at)
                    VALUES (?, ?, ?, ?, 'agent', ?, ?, ?)
                    """,
                    (
                        replacement_id,
                        agent_id,
                        agent["tenant_id"],
                        replacement_hash,
                        f"Rotated credential: {agent['hostname']}",
                        now_iso,
                        new_expiration,
                    ),
                )
                connection.execute(
                    "UPDATE agents SET current_token_hash = ? WHERE agent_id = ?",
                    (replacement_hash, agent_id),
                )
                connection.commit()

        replacement_data = {
            "agent_id": agent_id,
            "tenant_id": agent["tenant_id"],
            "expiration": new_expiration,
            "token": replacement,
            "renewed": True,
        }
        return replacement_data

    async def get_authenticated_agent_identity(
        self, token_str: str
    ) -> Optional[Dict[str, str]]:
        if not token_str:
            return None
        token_hash = self._token_key(token_str)
        now = self._utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            token = self._active_credential(connection, token_hash, now)
            if not token or token.get("token_type") != "agent":
                connection.rollback()
                return None
            connection.execute(
                "UPDATE agent_credentials SET last_used_at = ? WHERE token_hash = ?",
                (self._as_iso(now), token_hash),
            )
            connection.commit()
        return {
            "agent_id": token["agent_id"],
            "tenant_id": token["tenant_id"],
        }

    async def get_authenticated_agent_id(self, token_str: str) -> Optional[str]:
        identity = await self.get_authenticated_agent_identity(token_str)
        return identity["agent_id"] if identity else None

    async def validate_token(self, token_str: str) -> bool:
        return await self.get_authenticated_agent_identity(token_str) is not None

    async def list_tokens(self) -> List[Dict[str, Any]]:
        """List credential metadata without exposing credential values or hashes."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, agent_id, tenant_id, token_type, description, created_at,
                       expires_at AS expiration, revoked_at, last_used_at
                FROM agent_credentials ORDER BY created_at DESC
                """
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["token_id"] = item["id"]
            item["revoked"] = item["revoked_at"] is not None
            items.append(item)
        return items

    async def revoke_token(self, credential_id: str) -> bool:
        """Revoke one credential; agent credential revocation disables the agent."""
        now = self._as_iso(self._utc_now())
        if len(credential_id) != 36:
            credential_id = self._token_key(credential_id)
        async with self._token_lock:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                credential = connection.execute(
                    "SELECT * FROM agent_credentials WHERE id = ? OR token_hash = ?",
                    (credential_id, credential_id),
                ).fetchone()
                if not credential:
                    connection.rollback()
                    return False
                if credential["revoked_at"] is not None:
                    connection.rollback()
                    return False
                connection.execute(
                    "UPDATE agent_credentials SET revoked_at = ? WHERE id = ?",
                    (now, credential["id"]),
                )
                if credential["agent_id"]:
                    connection.execute(
                        "UPDATE agents SET status = 'revoked' WHERE agent_id = ?",
                        (credential["agent_id"],),
                    )
                    connection.execute(
                        """
                        UPDATE agent_credentials SET revoked_at = ?
                        WHERE agent_id = ? AND revoked_at IS NULL
                        """,
                        (now, credential["agent_id"]),
                    )
                connection.commit()
        return True

    async def record_heartbeat(self, agent_id: str) -> None:
        if agent_id:
            _IN_MEMORY_HEARTBEATS[agent_id] = time.time()

    async def is_redis_healthy(self) -> bool:
        """Check the Redis dependency used by the API rate limiter."""
        client = None
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
            )
            return bool(await client.ping())
        except Exception:
            return False
        finally:
            if client is not None:
                await client.aclose()


agent_service = AgentService()
