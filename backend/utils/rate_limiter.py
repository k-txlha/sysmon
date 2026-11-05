"""
backend/utils/rate_limiter.py

Sliding window rate limiter.
Uses Redis ZSET if available, with transparent in-memory sliding window fallback.
"""

import collections
import secrets
import time
from typing import DefaultDict, Deque
from fastapi import HTTPException, status
from starlette.requests import Request

from backend.config.settings import settings
from backend.utils.logger import setup_logger

logger = setup_logger("rate_limiter")

# In-memory sliding window fallback: identifier -> deque of timestamps
_IN_MEMORY_RATE_WINDOWS: DefaultDict[str, Deque[float]] = collections.defaultdict(collections.deque)


class RateLimiter:
    def __init__(
        self,
        requests_limit: int,
        window_seconds: int,
        key_by_client_ip: bool = False,
    ):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self.key_by_client_ip = key_by_client_ip
        self._redis_client = None
        self._redis_disabled = False

    async def _get_redis(self):
        if self._redis_disabled:
            return None
        if self._redis_client is None:
            try:
                import redis.asyncio as aioredis
                client = aioredis.from_url(
                    settings.REDIS_URL, decode_responses=True, socket_timeout=1
                )
                await client.ping()
                self._redis_client = client
            except Exception:
                self._redis_disabled = True
                self._redis_client = None
        return self._redis_client

    async def __call__(self, request: Request):
        try:
            body = await request.json()
            identifier = (
                body.get("agent_id")
                if isinstance(body, dict) and not self.key_by_client_ip
                else None
            )
            if not identifier:
                identifier = request.client.host if request.client else "unknown_ip"
        except Exception:
            identifier = request.client.host if request.client else "unknown_ip"

        now = time.time()
        window_start = now - self.window_seconds

        # Attempt Redis sliding window
        r = await self._get_redis()
        if r is not None:
            try:
                key = f"rate_limit:{identifier}"
                allowed = await r.eval(
                    """
                    local window_start = tonumber(ARGV[1]) - tonumber(ARGV[2])
                    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', window_start)
                    local request_count = redis.call('ZCARD', KEYS[1])
                    if request_count >= tonumber(ARGV[3]) then return 0 end
                    redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
                    redis.call('EXPIRE', KEYS[1], ARGV[2])
                    return 1
                    """,
                    1,
                    key,
                    now,
                    self.window_seconds,
                    self.requests_limit,
                    f"{now}:{secrets.token_hex(8)}",
                )
                if not allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail={
                            "error": "Too Many Requests",
                            "message": f"Rate limit exceeded. Maximum {self.requests_limit} requests per {self.window_seconds} seconds allowed.",
                        },
                    )
                return
            except HTTPException:
                raise
            except Exception as e:
                logger.debug(f"Redis rate limiter fallback due to: {e}")
                self._redis_disabled = True

        # In-Memory sliding window fallback
        timestamps = _IN_MEMORY_RATE_WINDOWS[identifier]
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        if len(timestamps) >= self.requests_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Maximum {self.requests_limit} requests per {self.window_seconds} seconds allowed.",
                },
            )

        timestamps.append(now)
