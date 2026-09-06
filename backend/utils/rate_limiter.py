"""
backend/utils/rate_limiter.py

Sliding window rate limiter.
Uses Redis ZSET if available, with transparent in-memory sliding window fallback.
"""

import collections
import time
from typing import DefaultDict, Deque
from fastapi import HTTPException, status
from starlette.requests import Request

from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("rate_limiter")

# In-memory sliding window fallback: identifier -> deque of timestamps
_IN_MEMORY_RATE_WINDOWS: DefaultDict[str, Deque[float]] = collections.defaultdict(collections.deque)


class RateLimiter:
    def __init__(self, requests_limit: int, window_seconds: int):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
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
            identifier = body.get("agent_id") if isinstance(body, dict) else None
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
                current_time = int(now)
                w_start_int = int(window_start)
                async with r.pipeline(transaction=True) as pipe:
                    pipe.zremrangebyscore(key, 0, w_start_int)
                    pipe.zcard(key)
                    pipe.zadd(key, {str(now): current_time})
                    pipe.expire(key, self.window_seconds)
                    _, request_count, _, _ = await pipe.execute()

                if request_count > self.requests_limit:
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
