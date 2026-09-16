"""
backend/api/v1/transport.py

High-throughput EDR telemetry ingestion endpoint.
Enforces the standardized Phase 0 EventEnvelope contract, validates agent
authorization tokens, tracks real-time heartbeats, stamps server receipt time,
and streams events into the Kafka pipeline.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import ValidationError

from config.settings import settings
from models.envelope import EventEnvelope, IngestionBatchRequest
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
async def receive_telemetry(payload: Union[IngestionBatchRequest, EventEnvelope, List[EventEnvelope], Dict[str, Any]]):
    """
    Ingests standardized EDR EventEnvelope payloads.
    Accepts a single EventEnvelope, an IngestionBatchRequest, or a list of EventEnvelopes.
    Strictly validates against the EventEnvelope data contract.
    """
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload received.",
        )

    envelopes: List[EventEnvelope] = []
    received_at_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        if isinstance(payload, IngestionBatchRequest):
            envelopes = payload.events
        elif isinstance(payload, EventEnvelope):
            envelopes = [payload]
        elif isinstance(payload, list):
            envelopes = [
                item if isinstance(item, EventEnvelope) else EventEnvelope.model_validate(item)
                for item in payload
            ]
        elif isinstance(payload, dict):
            if "events" in payload and isinstance(payload["events"], list):
                envelopes = [
                    EventEnvelope.model_validate(item) for item in payload["events"]
                ]
            else:
                envelopes = [EventEnvelope.model_validate(payload)]
    except (ValidationError, Exception) as val_err:
        logger.warning(f"Rejected non-conforming telemetry payload: {val_err}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid EventEnvelope schema: {val_err}",
        )

    if not envelopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid event envelopes found in request.",
        )

    # Record heartbeats and stream each envelope with server received_at timestamp
    unique_agents = set()
    for env in envelopes:
        env.received_at = received_at_ts
        unique_agents.add(env.agent_id)
        try:
            await kafka_service.stream_data(settings.KAFKA_TOPIC, env.model_dump(mode="json"))
        except Exception as e:
            logger.error(f"Failed to push event {env.event_id} to Kafka: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline ingestion failure.",
            )

    # Record heartbeats for all distinct agents in this batch
    for agent_id in unique_agents:
        await agent_service.record_heartbeat(agent_id)

    logger.debug(f"Ingested {len(envelopes)} event envelope(s) from {len(unique_agents)} agent(s).")
    return {
        "status": "accepted",
        "ingested_count": len(envelopes),
        "received_at": received_at_ts,
    }
