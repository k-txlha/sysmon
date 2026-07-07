import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status
from config.settings import settings
import time

# Initialize async redis client
redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)


class RateLimiter:
    def __init__(self, requests_limit: int, window_seconds: int):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds

    async def __call__(self, request: Request):
        # 1. Parse the request payload to get the agent_id
        # (Alternatively, fallback to client IP if payload is missing)
        try:
            body = await request.json()
            identifier = body.get("agent_id", request.client.host)
        except Exception:
            identifier = request.client.host

        key = f"rate_limit:{identifier}"
        current_time = int(time.time())
        window_start = current_time - self.window_seconds

        # Use a Redis Sorted Set (ZSET) to create a sliding window rate limiter
        async with redis_client.pipeline(transaction=True) as pipe:
            # Remove timestamps older than our current window
            pipe.zremrangebyscore(key, 0, window_start)
            # Count how many requests are left in this window
            pipe.zcard(key)
            # Add the current request timestamp
            pipe.zadd(key, {str(current_time): current_time})
            # Set an expiration on the key so it cleans up automatically later
            pipe.expire(key, self.window_seconds)

            # Execute the batch pipeline
            _, request_count, _, _ = await pipe.execute()

        # 2. Check if the limit has been crossed
        if request_count > self.requests_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Maximum {self.requests_limit} requests per {self.window_seconds} seconds allowed.",
                },
            )
