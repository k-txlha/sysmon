"""
backend/services/agent_service.py

Manages agent token generation, validation, revocation, enrollment handshakes,
and heartbeat tracking. Supports Redis storage with automatic in-memory fallback.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("agent_service")

# In-memory storage fallback if Redis is unavailable
_IN_MEMORY_TOKENS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_HEARTBEATS: Dict[str, float] = {}
_IN_MEMORY_ENROLLED_AGENTS: Dict[str, Dict[str, Any]] = {}
BOOTSTRAP_TOKEN_TTL = timedelta(hours=24)
AGENT_TOKEN_TTL = timedelta(hours=1)
TOKEN_RENEWAL_WINDOW = timedelta(minutes=5)


class AgentService:
    def __init__(self) -> None:
        self._redis_client = None
        self._token_lock = asyncio.Lock()

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

    async def generate_token(
        self, description: str = "Default Agent Token"
    ) -> Dict[str, Any]:
        """Generates a secure agent enrollment token."""
        token_str = f"sysmon_tok_{secrets.token_urlsafe(32)}"
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        token_data = {
            "token": token_str,
            "description": description,
            "created_at": now_iso,
            "last_used_at": None,
            "expiration": (now + BOOTSTRAP_TOKEN_TTL).isoformat(),
            "token_type": "bootstrap",
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

    async def _load_token(self, token_str: str) -> Optional[Dict[str, Any]]:
        r = await self._get_redis()
        if r:
            try:
                raw = await r.hget("sysmon:agent_tokens", token_str)
                if raw:
                    return json.loads(raw)
            except Exception as e:
                logger.warning(f"Redis error reading token ({e}), checking memory.")
        return _IN_MEMORY_TOKENS.get(token_str)

    async def _load_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        r = await self._get_redis()
        if r:
            try:
                raw = await r.hget("sysmon:enrolled_agents", agent_id)
                if raw:
                    return json.loads(raw)
            except Exception as e:
                logger.warning(f"Redis error reading agent ({e}), checking memory.")
        return _IN_MEMORY_ENROLLED_AGENTS.get(agent_id)

    @staticmethod
    def _expiration(token_data: Dict[str, Any]) -> Optional[datetime]:
        expiration = token_data.get("expiration")
        if not expiration:
            return None
        parsed = datetime.fromisoformat(expiration)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    async def _is_token_active(
        self, token_data: Dict[str, Any], now: datetime
    ) -> bool:
        if token_data.get("revoked", False):
            return False
        expiration = self._expiration(token_data)
        if expiration is not None and expiration <= now:
            return False

        agent_id = token_data.get("agent_id")
        if agent_id:
            agent = await self._load_agent(agent_id)
            if not agent or agent.get("status", "active") != "active":
                return False
        return True

    async def renew_token(self, token_str: str) -> Optional[Dict[str, Any]]:
        """Rotate an expiring agent credential without changing its identity."""
        async with self._token_lock:
            token_data = await self._load_token(token_str)
            now = datetime.now(timezone.utc)
            if (
                not token_data
                or not token_data.get("agent_id")
                or not await self._is_token_active(token_data, now)
            ):
                return None

            agent_id = token_data["agent_id"]
            agent = await self._load_agent(agent_id)
            if not agent or agent.get("status", "active") != "active":
                return None

            current_token = agent.get("current_token") or agent.get("agent_token")
            if current_token != token_str:
                replacement = token_data.get("superseded_by")
                if replacement != current_token:
                    return None
                current_data = await self._load_token(current_token)
                if (
                    not current_data
                    or current_data.get("agent_id") != agent_id
                    or not await self._is_token_active(current_data, now)
                ):
                    return None
                return {**current_data, "renewed": False}

            expiration = self._expiration(token_data)
            if expiration and expiration > now + TOKEN_RENEWAL_WINDOW:
                return {
                    **token_data,
                    "renewed": False,
                }

            new_token_str = f"sysmon_agent_{secrets.token_urlsafe(32)}"
            new_expiration = now + AGENT_TOKEN_TTL
            new_token_data = {
                "token": new_token_str,
                "description": token_data.get("description", f"Agent {agent_id}"),
                "created_at": now.isoformat(),
                "last_used_at": None,
                "expiration": new_expiration.isoformat(),
                "token_type": "agent",
                "agent_id": agent_id,
                "revoked": False,
            }
            # Keep the previous credential valid until its own expiry so requests
            # already in flight during rotation can complete.
            previous_token_data = {**token_data, "superseded_by": new_token_str}
            updated_agent = {
                **agent,
                "current_token": new_token_str,
                "agent_token": new_token_str,
            }

            r = await self._get_redis()
            if r:
                script = """
                local old_raw = redis.call('HGET', KEYS[1], ARGV[1])
                local agent_raw = redis.call('HGET', KEYS[2], ARGV[2])
                if not old_raw or not agent_raw then return 0 end
                local old = cjson.decode(old_raw)
                local agent = cjson.decode(agent_raw)
                if old.revoked == true or (agent.status and agent.status ~= 'active') then return 0 end
                local current = agent.current_token or agent.agent_token
                if current ~= ARGV[1] then return 0 end
                redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
                redis.call('HSET', KEYS[1], ARGV[4], ARGV[5])
                redis.call('HSET', KEYS[2], ARGV[2], ARGV[6])
                return 1
                """
                try:
                    stored = await r.eval(
                        script,
                        2,
                        "sysmon:agent_tokens",
                        "sysmon:enrolled_agents",
                        token_str,
                        agent_id,
                        json.dumps(previous_token_data),
                        new_token_str,
                        json.dumps(new_token_data),
                        json.dumps(updated_agent),
                    )
                    if not stored:
                        return None
                except Exception as e:
                    logger.error(f"Redis error atomically rotating agent token: {e}")
                    return None

            _IN_MEMORY_TOKENS[token_str] = previous_token_data
            _IN_MEMORY_TOKENS[new_token_str] = new_token_data
            _IN_MEMORY_ENROLLED_AGENTS[agent_id] = updated_agent
            return {**new_token_data, "renewed": True}

    async def validate_token(self, token_str: str) -> bool:
        """Validates if a given token is active and not revoked."""
        if not token_str:
            return False

        data = await self._load_token(token_str)
        now = datetime.now(timezone.utc)
        if not data or not await self._is_token_active(data, now):
            return False

        last_used_at = now.isoformat()
        if _IN_MEMORY_TOKENS.get(token_str) is data:
            data["last_used_at"] = last_used_at
        r = await self._get_redis()
        if r:
            try:
                await r.eval(
                    """
                    local raw = redis.call('HGET', KEYS[1], ARGV[1])
                    if not raw then return 0 end
                    local token = cjson.decode(raw)
                    if token.revoked == true then return 0 end
                    token.last_used_at = ARGV[2]
                    redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(token))
                    return 1
                    """,
                    1,
                    "sysmon:agent_tokens",
                    token_str,
                    last_used_at,
                )
            except Exception as e:
                logger.warning(f"Redis error updating token usage ({e}).")
        return True

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
        Consumes a valid bootstrap token and issues a dedicated agent identity
        with a renewable, expiring credential.
        """
        async with self._token_lock:
            bootstrap = await self._load_token(bootstrap_token)
            now = datetime.now(timezone.utc)
            if (
                not bootstrap
                or bootstrap.get("token_type", "bootstrap") != "bootstrap"
                or not await self._is_token_active(bootstrap, now)
            ):
                return None

            agent_id = hostname or f"agent-{uuid.uuid4().hex[:8]}"
            existing_agent = await self._load_agent(agent_id)
            if existing_agent:
                logger.warning(f"Refusing duplicate enrollment for agent '{agent_id}'.")
                return None

            agent_token = f"sysmon_agent_{secrets.token_urlsafe(32)}"
            now_iso = now.isoformat()
            expiration = now + AGENT_TOKEN_TTL
            enrollment_record = {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "agent_token": agent_token,
                "current_token": agent_token,
                "hostname": hostname,
                "operating_system": operating_system,
                "mac_address": mac_address,
                "machine_architecture": machine_architecture,
                "enrolled_at": now_iso,
                "status": "active",
            }
            token_data = {
                "token": agent_token,
                "description": f"Enrolled Agent: {hostname} ({agent_id})",
                "created_at": now_iso,
                "last_used_at": now_iso,
                "expiration": expiration.isoformat(),
                "token_type": "agent",
                "agent_id": agent_id,
                "revoked": False,
            }
            bootstrap.update({"revoked": True, "used_at": now_iso})

            r = await self._get_redis()
            if r:
                try:
                    async with r.pipeline(transaction=True) as pipe:
                        pipe.hset(
                            "sysmon:agent_tokens",
                            mapping={
                                bootstrap_token: json.dumps(bootstrap),
                                agent_token: json.dumps(token_data),
                            },
                        )
                        pipe.hset(
                            "sysmon:enrolled_agents",
                            agent_id,
                            json.dumps(enrollment_record),
                        )
                        await pipe.execute()
                except Exception as e:
                    logger.warning(f"Redis error saving enrolled agent ({e}).")

            _IN_MEMORY_TOKENS[bootstrap_token] = bootstrap
            _IN_MEMORY_TOKENS[agent_token] = token_data
            _IN_MEMORY_ENROLLED_AGENTS[agent_id] = enrollment_record
            enrollment_record["expires_at"] = expiration.isoformat()
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
                logger.warning(
                    f"Redis error listing tokens ({e}), using in-memory store."
                )

        return list(tokens_map.values())

    async def revoke_token(self, token_str: str) -> bool:
        """Revokes an existing agent token."""
        async with self._token_lock:
            token_data = await self._load_token(token_str)
            if not token_data:
                return False
            token_data["revoked"] = True
            agent_id = token_data.get("agent_id")
            agent = await self._load_agent(agent_id) if agent_id else None
            if agent:
                agent["status"] = "revoked"

            r = await self._get_redis()
            if r:
                try:
                    async with r.pipeline(transaction=True) as pipe:
                        pipe.hset("sysmon:agent_tokens", token_str, json.dumps(token_data))
                        if agent and agent_id:
                            pipe.hset(
                                "sysmon:enrolled_agents",
                                agent_id,
                                json.dumps(agent),
                            )
                        await pipe.execute()
                except Exception as e:
                    logger.warning(f"Redis error revoking token ({e}), revoked in memory.")

            _IN_MEMORY_TOKENS[token_str] = token_data
            if agent and agent_id:
                _IN_MEMORY_ENROLLED_AGENTS[agent_id] = agent
            return True

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
