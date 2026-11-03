from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from services.agent_service import (
    _IN_MEMORY_ENROLLED_AGENTS,
    _IN_MEMORY_TOKENS,
    AgentService,
)


def _service_without_redis() -> AgentService:
    service = AgentService()

    async def no_redis():
        return None

    service._get_redis = no_redis
    return service


def test_renewal_rotates_token_without_changing_agent_identity():
    async def scenario():
        service = _service_without_redis()
        bootstrap = await service.generate_token()
        enrolled = await service.enroll_agent(
            bootstrap["token"],
            hostname="renewal-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:55",
        )
        assert enrolled is not None
        old_token = enrolled["agent_token"]
        _IN_MEMORY_TOKENS[old_token]["expiration"] = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()

        replacement = await service.renew_token(old_token)

        assert replacement is not None
        assert replacement["renewed"] is True
        assert replacement["token"] != old_token
        assert replacement["agent_id"] == enrolled["agent_id"]
        assert _IN_MEMORY_ENROLLED_AGENTS[enrolled["agent_id"]]["current_token"] == replacement["token"]
        assert await service.validate_token(old_token)
        assert await service.validate_token(replacement["token"])

        recovered = await service.renew_token(old_token)
        assert recovered is not None
        assert recovered["renewed"] is False
        assert recovered["token"] == replacement["token"]

    asyncio.run(scenario())


def test_renewal_rejects_revoked_agent_and_reenrollment():
    async def scenario():
        service = _service_without_redis()
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
        assert await service.enroll_agent(
            fresh_bootstrap["token"],
            hostname="revoked-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:66",
        ) is None

    asyncio.run(scenario())


def test_renewal_rejects_inactive_agent():
    async def scenario():
        service = _service_without_redis()
        bootstrap = await service.generate_token()
        enrolled = await service.enroll_agent(
            bootstrap["token"],
            hostname="inactive-test-agent",
            operating_system="Linux",
            mac_address="00:11:22:33:44:88",
        )
        assert enrolled is not None
        token = enrolled["agent_token"]
        _IN_MEMORY_TOKENS[token]["expiration"] = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        _IN_MEMORY_ENROLLED_AGENTS[enrolled["agent_id"]]["status"] = "inactive"

        assert await service.renew_token(token) is None

    asyncio.run(scenario())


def test_expired_and_revoked_bootstrap_tokens_cannot_enroll():
    async def scenario():
        service = _service_without_redis()
        expired = await service.generate_token()
        _IN_MEMORY_TOKENS[expired["token"]]["expiration"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        assert await service.enroll_agent(
            expired["token"], "expired-agent", "Linux", "00:00:00:00:00:01"
        ) is None

        revoked = await service.generate_token()
        assert await service.revoke_token(revoked["token"])
        assert await service.enroll_agent(
            revoked["token"], "revoked-bootstrap-agent", "Linux", "00:00:00:00:00:02"
        ) is None

    asyncio.run(scenario())
