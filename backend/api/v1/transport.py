"""
backend/api/v1/transport.py

High-throughput telemetry ingestion endpoint.
Receives host metrics and Windows Security Event logs from agents,
validates authorization if configured, tracks heartbeats,
and streams the payload into Kafka.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status

from config.settings import settings
from services.agent_service import agent_service
from services.producer import kafka_service
from utils.logger import setup_logger
from utils.rate_limiter import RateLimiter

router = APIRouter(prefix="/api/v1", tags=["Ingestion"])
logger = setup_logger("transport")

# Rate limiter instance
rate_limiter = RateLimiter(requests_limit=10, window_seconds=10)


async def verify_agent_auth(
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(default=None),
) -> None:
    """Validates the agent token when REQUIRE_AGENT_AUTH is enabled."""
    if not settings.REQUIRE_AGENT_AUTH:
        return

    token = x_agent_token
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent authentication token header (X-Agent-Token or Authorization).",
        )

    is_valid = await agent_service.validate_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked agent token.",
        )


@router.post(
    "/telemetry",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limiter), Depends(verify_agent_auth)],
)
async def receive_telemetry(payload: dict):
    if not payload:
        raise HTTPException(status_code=400, detail="Empty payload received.")

    # Record agent heartbeat
    agent_id = (
        payload.get("agent_id")
        or payload.get("device_info", {}).get("agent_id")
        or (payload.get("devices", [{}])[0].get("agent_id") if isinstance(payload.get("devices"), list) and payload.get("devices") else None)
    )
    if agent_id:
        await agent_service.record_heartbeat(agent_id)

    try:
        await kafka_service.stream_data(settings.KAFKA_TOPIC, payload)
        return {"status": "accepted", "message": "Log queued into pipeline."}
    except Exception as e:
        logger.error(f"[ERROR] Failed to push message to Kafka: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Pipeline ingestion failure.",
        )
