"""
backend/api/v1/health.py

Health check endpoints reporting the status of backend dependencies:
- Kafka Producer
- ClickHouse DB Connection
- Redis Cache
"""

import time
from fastapi import APIRouter
from services.producer import kafka_service
from services.ch_service import ch_service
from services.agent_service import agent_service
from utils.logger import setup_logger

router = APIRouter(tags=["Health"])
logger = setup_logger("health_api")

START_TIME = time.time()


@router.get("/health")
async def health_check():
    """
    Comprehensive system health check.
    Checks connectivity to Kafka, ClickHouse, and Redis.
    """
    ch_ok = ch_service.is_healthy()
    redis_ok = await agent_service.is_redis_healthy()
    kafka_ok = kafka_service.producer is not None

    uptime_seconds = int(time.time() - START_TIME)
    is_healthy = ch_ok and kafka_ok

    return {
        "status": "healthy" if is_healthy else "degraded",
        "uptime_seconds": uptime_seconds,
        "services": {
            "kafka": "connected" if kafka_ok else "disconnected",
            "clickhouse": "connected" if ch_ok else "disconnected",
            "redis": "connected" if redis_ok else "in_memory_fallback",
        },
    }
