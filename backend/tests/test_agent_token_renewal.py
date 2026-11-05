from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.services.agent_service import (
    AgentService,
)
from backend.services.auth_service import auth_service


def _service_without_redis(database_path: Path) -> AgentService:
    auth_service.database_path = database_path
    service = AgentService()

    return service


def _set_expiration(token: str, expiration: datetime) -> None:
    with closing(
        sqlite3.connect(auth_service.database_path, isolation_level=None)
    ) as connection:
        connection.execute(
            "UPDATE agent_credentials SET expires_at = ? WHERE token_hash = ?",
            (expiration.isoformat(), AgentService._token_key(token)),
        )


def test_renewal_rotates_token_without_changing_agent_identity(tmp_path: Path):
    async def scenario():
        service = _service_without_redis(tmp_path / "auth.db")
        bootstrap = await service.generate_token()
        enrolled = await service.enroll_agent(
            bootstrap["token"],
            hostname="renewal-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:55",
        )
        assert enrolled is not None
        old_token = enrolled["agent_token"]
        _set_expiration(old_token, datetime.now(timezone.utc) + timedelta(minutes=1))

        replacement = await service.renew_token(old_token)

        assert replacement is not None
        assert replacement["renewed"] is True
        assert replacement["token"] != old_token
        assert replacement["agent_id"] == enrolled["agent_id"]
        with closing(
            sqlite3.connect(auth_service.database_path)
        ) as connection:
            current_hash = connection.execute(
                "SELECT current_token_hash FROM agents WHERE agent_id = ?",
                (enrolled["agent_id"],),
            ).fetchone()[0]
        assert current_hash == service._token_key(replacement["token"])
        assert await service.validate_token(old_token)
        assert await service.validate_token(replacement["token"])

        recovered = await service.renew_token(old_token)
        assert recovered is not None
        assert recovered["renewed"] is True
        assert recovered["token"] != replacement["token"]
        assert recovered["agent_id"] == replacement["agent_id"]
        _set_expiration(old_token, datetime.now(timezone.utc) - timedelta(seconds=1))
        assert not await service.validate_token(old_token)
        assert await service.validate_token(recovered["token"])

    asyncio.run(scenario())


def test_renewal_rejects_revoked_agent_and_allows_fresh_enrollment(tmp_path: Path):
    async def scenario():
        service = _service_without_redis(tmp_path / "auth.db")
        bootstrap = await service.generate_token()
        enrolled = await service.enroll_agent(
            bootstrap["token"],
            hostname="revoked-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:66",
        )
        assert enrolled is not None
        agent_token = enrolled["agent_token"]

        assert await service.revoke_token(agent_token)
        assert await service.renew_token(agent_token) is None
        assert not await service.validate_token(agent_token)

        fresh_bootstrap = await service.generate_token()
        re_enrolled = await service.enroll_agent(
            fresh_bootstrap["token"],
            hostname="revoked-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:66",
        )
        assert re_enrolled is not None
        assert re_enrolled["agent_id"] != enrolled["agent_id"]

    asyncio.run(scenario())


def test_renewal_rejects_inactive_agent(tmp_path: Path):
    async def scenario():
        service = _service_without_redis(tmp_path / "auth.db")
        bootstrap = await service.generate_token()
        enrolled = await service.enroll_agent(
            bootstrap["token"],
            hostname="inactive-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:88",
        )
        assert enrolled is not None
        token = enrolled["agent_token"]
        _set_expiration(token, datetime.now(timezone.utc) + timedelta(minutes=1))
        with closing(
            sqlite3.connect(auth_service.database_path, isolation_level=None)
        ) as connection:
            connection.execute(
                "UPDATE agents SET status = 'inactive' WHERE agent_id = ?",
                (enrolled["agent_id"],),
            )

        assert await service.renew_token(token) is None

    asyncio.run(scenario())


def test_expired_and_revoked_bootstrap_tokens_cannot_enroll(tmp_path: Path):
    async def scenario():
        service = _service_without_redis(tmp_path / "auth.db")
        expired = await service.generate_token()
        _set_expiration(expired["token"], datetime.now(timezone.utc) - timedelta(seconds=1))
        assert await service.enroll_agent(
            expired["token"], "expired-agent", "Linux", "00:00:00:00:00:01"
        ) is None

        revoked = await service.generate_token()
        assert await service.revoke_token(revoked["token"])
        assert await service.enroll_agent(
            revoked["token"], "revoked-bootstrap-agent", "Linux", "00:00:00:00:00:02"
        ) is None

    asyncio.run(scenario())
