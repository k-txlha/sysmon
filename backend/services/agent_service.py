"""
backend/services/agent_service.py

Manages agent token generation, validation, revocation, enrollment handshakes,
and heartbeat tracking. Supports Redis storage with automatic in-memory fallback.
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("agent_service")

# In-memory storage fallback if Redis is unavailable
_IN_MEMORY_TOKENS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_HEARTBEATS: Dict[str, float] = {}
_IN_MEMORY_ENROLLED_AGENTS: Dict[str, Dict[str, Any]] = {}


class AgentService:
    def __init__(self) -> None:
        self._redis_client = None

    async def _get_redis(self):
        try:
            import redis.asyncio as aioredis
            if self._redis_client is None:
                self._redis_client = aioredis.from_url(
                    settings.REDIS_URL, decode_responses=True, socket_timeout=2
                )
            await self._redis_client.ping()
            return self._redis_client
        except Exception:
            self._redis_client = None
            return None

    async def generate_token(self, description: str = "Default Agent Token") -> Dict[str, Any]:
        """Generates a secure agent enrollment token."""
        token_str = f"sysmon_tok_{secrets.token_urlsafe(32)}"
        now_iso = datetime.now(timezone.utc).isoformat()
        token_data = {
            "token": token_str,
            "description": description,
            "created_at": now_iso,
            "last_used_at": None,
            "revoked": False,
        }

        # Always save to in-memory store
        _IN_MEMORY_TOKENS[token_str] = token_data

        r = await self._get_redis()
        if r:
            try:
                await r.hset("sysmon:agent_tokens", token_str, json.dumps(token_data))
            except Exception as e:
                logger.warning(f"Redis error saving token ({e}), stored in memory.")

        return token_data

    async def validate_token(self, token_str: str) -> bool:
        """Validates if a given token is active and not revoked."""
        if not token_str:
            return False

        r = await self._get_redis()
        if r:
            try:
                raw = await r.hget("sysmon:agent_tokens", token_str)
                if raw:
                    data = json.loads(raw)
                    if not data.get("revoked", False):
                        data["last_used_at"] = datetime.now(timezone.utc).isoformat()
                        await r.hset("sysmon:agent_tokens", token_str, json.dumps(data))
                        _IN_MEMORY_TOKENS[token_str] = data
                        return True
            except Exception as e:
                logger.warning(f"Redis error validating token ({e}), checking in-memory store.")

        if token_str in _IN_MEMORY_TOKENS:
            data = _IN_MEMORY_TOKENS[token_str]
            if not data.get("revoked", False):
                data["last_used_at"] = datetime.now(timezone.utc).isoformat()
                return True

        return False

    async def enroll_agent(
        self,
        bootstrap_token: str,
        hostname: str,
        operating_system: str,
        mac_address: str,
        machine_architecture: str = "x86_64",
        tenant_id: str = "default",
    ) -> Optional[Dict[str, Any]]:
        """
        Validates the bootstrap token and issues a permanent, dedicated agent identity and token.
        """
        is_valid = await self.validate_token(bootstrap_token)
        if not is_valid:
            return None

        # Generate a dedicated, permanent agent token
        agent_id = hostname or f"agent-{uuid.uuid4().hex[:8]}"
        agent_token = f"sysmon_agent_{secrets.token_urlsafe(32)}"
        now_iso = datetime.now(timezone.utc).isoformat()

        enrollment_record = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "agent_token": agent_token,
            "hostname": hostname,
            "operating_system": operating_system,
            "mac_address": mac_address,
            "machine_architecture": machine_architecture,
            "enrolled_at": now_iso,
        }

        token_data = {
            "token": agent_token,
            "description": f"Enrolled Agent: {hostname} ({agent_id})",
            "created_at": now_iso,
            "last_used_at": now_iso,
            "revoked": False,
        }
        _IN_MEMORY_TOKENS[agent_token] = token_data
        _IN_MEMORY_ENROLLED_AGENTS[agent_id] = enrollment_record

        r = await self._get_redis()
        if r:
            try:
                await r.hset("sysmon:agent_tokens", agent_token, json.dumps(token_data))
                await r.hset("sysmon:enrolled_agents", agent_id, json.dumps(enrollment_record))
            except Exception as e:
                logger.warning(f"Redis error saving enrolled agent ({e})")

        return enrollment_record

    async def list_tokens(self) -> List[Dict[str, Any]]:
        """Lists all registered agent enrollment tokens (merging Redis and in-memory)."""
        tokens_map = dict(_IN_MEMORY_TOKENS)
        r = await self._get_redis()
        if r:
            try:
                raw_dict = await r.hgetall("sysmon:agent_tokens")
                if raw_dict:
                    for val in raw_dict.values():
                        tok_obj = json.loads(val)
                        tokens_map[tok_obj["token"]] = tok_obj
            except Exception as e:
                logger.warning(f"Redis error listing tokens ({e}), using in-memory store.")

        return list(tokens_map.values())

    async def revoke_token(self, token_str: str) -> bool:
        """Revokes an existing agent token."""
        if token_str in _IN_MEMORY_TOKENS:
            _IN_MEMORY_TOKENS[token_str]["revoked"] = True

        r = await self._get_redis()
        if r:
            try:
                raw = await r.hget("sysmon:agent_tokens", token_str)
                if raw:
                    data = json.loads(raw)
                    data["revoked"] = True
                    await r.hset("sysmon:agent_tokens", token_str, json.dumps(data))
                    return True
            except Exception as e:
                logger.warning(f"Redis error revoking token ({e}), revoked in memory.")

        return token_str in _IN_MEMORY_TOKENS

    async def record_heartbeat(self, agent_id: str) -> None:
        """Records the latest activity timestamp for an agent."""
        if not agent_id:
            return
        now_ts = time.time()
        _IN_MEMORY_HEARTBEATS[agent_id] = now_ts
        r = await self._get_redis()
        if r:
            try:
                await r.hset("sysmon:agent_heartbeats", agent_id, str(now_ts))
            except Exception:
                pass

    async def is_redis_healthy(self) -> bool:
        """Checks if Redis is connected and responsive."""
        r = await self._get_redis()
        if not r:
            return False
        try:
            return bool(await r.ping())
        except Exception:
            return False


agent_service = AgentService()
