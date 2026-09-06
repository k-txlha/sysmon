"""
backend/services/agent_service.py

Manages agent token generation, validation, revocation, and heartbeat tracking.
Supports Redis storage with automatic in-memory fallback for testing/standalone modes.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("agent_service")

# In-memory storage fallback if Redis is unavailable
_IN_MEMORY_TOKENS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_HEARTBEATS: Dict[str, float] = {}


class AgentService:
    def __init__(self) -> None:
        self._redis_client = None

    async def _get_redis(self):
        if self._redis_client is None:
            try:
                import redis.asyncio as aioredis
                self._redis_client = aioredis.from_url(
                    settings.REDIS_URL, decode_responses=True, socket_timeout=2
                )
                await self._redis_client.ping()
            except Exception as e:
                logger.debug(f"Redis unavailable for agent service ({e}), using in-memory store.")
                self._redis_client = False
        return self._redis_client if self._redis_client is not False else None

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

        r = await self._get_redis()
        if r:
            try:
                import json
                await r.hset("sysmon:agent_tokens", token_str, json.dumps(token_data))
                return token_data
            except Exception as e:
                logger.warning(f"Redis error saving token: {e}")

        _IN_MEMORY_TOKENS[token_str] = token_data
        return token_data

    async def validate_token(self, token_str: str) -> bool:
        """Validates if a given token is active and not revoked."""
        if not token_str:
            return False

        r = await self._get_redis()
        if r:
            try:
                import json
                raw = await r.hget("sysmon:agent_tokens", token_str)
                if raw:
                    data = json.loads(raw)
                    if not data.get("revoked", False):
                        data["last_used_at"] = datetime.now(timezone.utc).isoformat()
                        await r.hset("sysmon:agent_tokens", token_str, json.dumps(data))
                        return True
            except Exception as e:
                logger.warning(f"Redis error validating token: {e}")

        if token_str in _IN_MEMORY_TOKENS:
            data = _IN_MEMORY_TOKENS[token_str]
            if not data.get("revoked", False):
                data["last_used_at"] = datetime.now(timezone.utc).isoformat()
                return True

        return False

    async def list_tokens(self) -> List[Dict[str, Any]]:
        """Lists all registered agent enrollment tokens."""
        r = await self._get_redis()
        if r:
            try:
                import json
                raw_dict = await r.hgetall("sysmon:agent_tokens")
                tokens = []
                for val in raw_dict.values():
                    tokens.append(json.loads(val))
                return tokens
            except Exception as e:
                logger.warning(f"Redis error listing tokens: {e}")

        return list(_IN_MEMORY_TOKENS.values())

    async def revoke_token(self, token_str: str) -> bool:
        """Revokes an existing agent token."""
        r = await self._get_redis()
        if r:
            try:
                import json
                raw = await r.hget("sysmon:agent_tokens", token_str)
                if raw:
                    data = json.loads(raw)
                    data["revoked"] = True
                    await r.hset("sysmon:agent_tokens", token_str, json.dumps(data))
                    return True
            except Exception as e:
                logger.warning(f"Redis error revoking token: {e}")

        if token_str in _IN_MEMORY_TOKENS:
            _IN_MEMORY_TOKENS[token_str]["revoked"] = True
            return True

        return False

    async def record_heartbeat(self, agent_id: str) -> None:
        """Records the latest activity timestamp for an agent."""
        if not agent_id:
            return
        now_ts = time.time()
        r = await self._get_redis()
        if r:
            try:
                await r.hset("sysmon:agent_heartbeats", agent_id, str(now_ts))
                return
            except Exception:
                pass
        _IN_MEMORY_HEARTBEATS[agent_id] = now_ts

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
