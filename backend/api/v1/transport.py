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

from backend.config.settings import settings
from backend.models.envelope import EventEnvelope, IngestionBatchRequest
from backend.services.agent_service import agent_service
from backend.services.producer import kafka_service
from backend.utils.logger import setup_logger
from backend.utils.rate_limiter import RateLimiter
from backend.utils.request_security import uses_secure_agent_transport

router = APIRouter(prefix="/api/v1", tags=["Ingestion"])
logger = setup_logger("transport")

# Rate limiter instance
rate_limiter = RateLimiter(requests_limit=10, window_seconds=10)


async def verify_agent_auth(
    request: Request,
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, str]:
    """Validates the agent token and returns its backend-bound identity."""
    if not uses_secure_agent_transport(request):
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail="Agent telemetry requires HTTPS.",
        )
    bearer_token = None
    if authorization:
        scheme, separator, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not value.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed agent Authorization header.",
            )
        bearer_token = value.strip()
    if x_agent_token and bearer_token and x_agent_token != bearer_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Conflicting agent credentials.",
        )
    token = bearer_token or x_agent_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent authentication credential.",
        )

    identity = await agent_service.get_authenticated_agent_identity(token)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked agent credential.",
        )
    return identity


@router.post(
    "/telemetry",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limiter)],
)
async def receive_telemetry(
    payload: Union[IngestionBatchRequest, EventEnvelope, List[EventEnvelope], Dict[str, Any]],
    authenticated_identity: Dict[str, str] = Depends(verify_agent_auth),
):
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
    event_ids = [envelope.event_id for envelope in envelopes]
    if len(set(event_ids)) != len(event_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A telemetry batch cannot contain duplicate event IDs.",
        )

    # Stamp server receipt time and stream batch to Kafka
    unique_agents = set()
    raw_envelopes = []
    for env in envelopes:
        if env.agent_id != authenticated_identity["agent_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Telemetry agent_id does not match the authenticated identity.",
            )
        if env.tenant_id != authenticated_identity["tenant_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Telemetry tenant_id does not match the authenticated tenant.",
            )
        env.agent_id = authenticated_identity["agent_id"]
        env.tenant_id = authenticated_identity["tenant_id"]
        env.received_at = received_at_ts
        unique_agents.add(env.agent_id)
        raw_envelopes.append(env.model_dump(mode="json"))

    try:
        with agent_service.telemetry_receipt_transaction(
            authenticated_identity["agent_id"], event_ids
        ) as (accepted_before, receipt_connection):
            new_envelopes = [
                envelope
                for envelope in raw_envelopes
                if envelope["event_id"] not in accepted_before
            ]
            if new_envelopes:
                await kafka_service.stream_batch(settings.KAFKA_TOPIC, new_envelopes)
                agent_service.record_accepted_events(
                    authenticated_identity["agent_id"],
                    [envelope["event_id"] for envelope in new_envelopes],
                    connection=receipt_connection,
                )
    except Exception as e:
        logger.error(
            "Failed to durably accept telemetry batch: %s",
            type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telemetry was not durably accepted; retry the batch.",
        )

    # Record heartbeats for all distinct agents in this batch
    for agent_id in unique_agents:
        await agent_service.record_heartbeat(agent_id)

    logger.debug(f"Ingested {len(envelopes)} event envelope(s) from {len(unique_agents)} agent(s).")
    return {
        "status": "accepted",
        "ingested_count": len(envelopes),
        "accepted_event_ids": event_ids,
        "received_at": received_at_ts,
    }
