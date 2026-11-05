"""Local SQLite-backed administrator authentication and session storage."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator, Optional

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from backend.config.settings import settings

SESSION_TTL = timedelta(hours=12)
AUTH_SESSION_COOKIE = "sysmon_admin_session"
CSRF_HEADER = "X-CSRF-Token"

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    type=Type.ID,
)
_COMMON_PASSWORDS = {
    "password",
    "password123",
    "password1234",
    "password123456",
    "123456789012",
    "qwerty123456",
    "letmein123456",
    "admin123456",
    "changeme123",
}
_COMMON_PASSWORD_PREFIXES = (
    "password",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
    "changeme",
    "iloveyou",
)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


class AuthenticationInputError(ValueError):
    """Raised when a new administrator password or username violates policy."""


class AdministratorAlreadyExists(RuntimeError):
    """Raised when the one-time setup has already completed."""


@dataclass(frozen=True)
class AuthenticatedAdmin:
    id: str
    session_id: str
    username: str
    role: str
    csrf_token_hash: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_username(username: str) -> str:
    normalized = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", normalized):
        raise AuthenticationInputError(
            "Username must be 3-64 characters and use letters, numbers, '.', '_' or '-'."
        )
    return normalized


def _validate_password(password: str, username: str) -> None:
    if not 12 <= len(password) <= 128:
        raise AuthenticationInputError("Password must be between 12 and 128 characters.")
    normalized = password.strip().lower()
    if (
        normalized in _COMMON_PASSWORDS
        or normalized == username.strip().lower()
        or normalized.startswith(_COMMON_PASSWORD_PREFIXES)
    ):
        raise AuthenticationInputError("Choose a less common password.")
    if len(set(password)) <= 3:
        raise AuthenticationInputError("Choose a less common password.")


class AuthService:
    def __init__(self) -> None:
        self.database_path = Path(settings.AUTH_DB_PATH)
        self._initialized_path: Optional[Path] = None
        self._initialization_lock = threading.Lock()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        current_path = self.database_path.resolve()
        if self._initialized_path == current_path and current_path.exists():
            return
        with self._initialization_lock:
            if self._initialized_path == current_path and current_path.exists():
                return
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS admin_users (
                        id TEXT PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'admin'
                            CHECK (role IN ('admin', 'analyst', 'viewer')),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1
                            CHECK (is_active IN (0, 1))
                    );
                    CREATE TABLE IF NOT EXISTS admin_sessions (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
                        session_token_hash TEXT NOT NULL UNIQUE,
                        csrf_token_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        revoked_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_admin_sessions_user
                        ON admin_sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiration
                        ON admin_sessions(expires_at);
                    CREATE TABLE IF NOT EXISTS system_settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
            if os.name == "nt":
                identity = subprocess.run(
                    ["whoami"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                subprocess.run(
                    ["icacls", str(self.database_path), "/reset"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    [
                        "icacls",
                        str(self.database_path),
                        "/inheritance:r",
                        "/grant:r",
                        f"{identity}:(F)",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            else:
                os.chmod(self.database_path, 0o600)
            self._initialized_path = current_path

    def is_setup_required(self) -> bool:
        self.initialize()
        with self._connect() as connection:
            return connection.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone() is None

    def create_admin(self, username: str, password: str) -> dict[str, str]:
        normalized_username = _validate_username(username)
        _validate_password(password, normalized_username)
        password_hash = _PASSWORD_HASHER.hash(password)
        now = _to_iso(_utc_now())
        user_id = str(uuid.uuid4())
        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM admin_users LIMIT 1"
            ).fetchone()
            if existing:
                connection.rollback()
                raise AdministratorAlreadyExists
            connection.execute(
                """
                INSERT INTO admin_users
                    (id, username, password_hash, role, created_at, updated_at, is_active)
                VALUES (?, ?, ?, 'admin', ?, ?, 1)
                """,
                (user_id, normalized_username, password_hash, now, now),
            )
            connection.commit()
        return {"id": user_id, "username": normalized_username, "role": "admin"}

    def authenticate(self, username: str, password: str) -> Optional[dict[str, str]]:
        self.initialize()
        with self._connect() as connection:
            user = connection.execute(
                """
                SELECT id, username, password_hash, role
                FROM admin_users
                WHERE username = ? COLLATE NOCASE AND is_active = 1
                """,
                (username.strip(),),
            ).fetchone()

        encoded_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
        verified = False
        try:
            verified = _PASSWORD_HASHER.verify(encoded_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            verified = False
        if not user or not verified:
            return None
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

    def create_session(self, user_id: str) -> tuple[str, str, str]:
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = _utc_now()
        expires_at = now + SESSION_TTL
        self.initialize()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO admin_sessions
                    (id, user_id, session_token_hash, csrf_token_hash, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    user_id,
                    hash_token(session_token),
                    hash_token(csrf_token),
                    _to_iso(now),
                    _to_iso(expires_at),
                ),
            )
        return session_token, csrf_token, _to_iso(expires_at)

    def get_session(self, session_token: str) -> Optional[AuthenticatedAdmin]:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT u.id, s.id AS session_id, u.username, u.role, s.csrf_token_hash
                FROM admin_sessions AS s
                JOIN admin_users AS u ON u.id = s.user_id
                WHERE s.session_token_hash = ?
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?
                    AND u.is_active = 1
                """,
                (hash_token(session_token), _to_iso(_utc_now())),
            ).fetchone()
        if row is None:
            return None
        return AuthenticatedAdmin(
            id=row["id"],
            session_id=row["session_id"],
            username=row["username"],
            role=row["role"],
            csrf_token_hash=row["csrf_token_hash"],
        )

    def validate_csrf(self, admin: AuthenticatedAdmin, csrf_token: str) -> bool:
        return hmac.compare_digest(admin.csrf_token_hash, hash_token(csrf_token))

    def rotate_csrf(self, session_id: str) -> str:
        csrf_token = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE admin_sessions SET csrf_token_hash = ?
                WHERE id = ? AND revoked_at IS NULL
                """,
                (hash_token(csrf_token), session_id),
            )
        return csrf_token

    def revoke_session(self, session_token: str) -> None:
        self.initialize()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE admin_sessions SET revoked_at = ?
                WHERE session_token_hash = ? AND revoked_at IS NULL
                """,
                (_to_iso(_utc_now()), hash_token(session_token)),
            )

    def change_password(self, user_id: str, password: str) -> None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT username FROM admin_users WHERE id = ? AND is_active = 1",
                (user_id,),
            ).fetchone()
        if row is None:
            raise LookupError("Administrator account is unavailable.")
        _validate_password(password, row["username"])
        password_hash = _PASSWORD_HASHER.hash(password)
        now = _to_iso(_utc_now())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (password_hash, now, user_id),
            )
            connection.execute(
                """
                UPDATE admin_sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (now, user_id),
            )
            connection.commit()

    def recover_password(self, username: str, password: str) -> None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id FROM admin_users WHERE username = ? COLLATE NOCASE",
                (username.strip(),),
            ).fetchone()
        if row is None:
            raise LookupError("Administrator account was not found.")
        self.change_password(row["id"], password)


auth_service = AuthService()
