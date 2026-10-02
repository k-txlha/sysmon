"""
backend/api/v1/agents.py

REST API router for Agent Management:
- Enumerate connected and registered telemetry agents
- Provision and manage agent enrollment API tokens
- Agent enrollment handshake endpoint
- Token validation and revocation
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from services.agent_service import agent_service
from services.ch_service import ch_service
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])
logger = setup_logger("agents_api")


class GenerateTokenRequest(BaseModel):
    description: str = Field(
        default="Production Agent Token",
        description="Human-readable label for the provisioned agent token.",
    )


class AgentEnrollRequest(BaseModel):
    bootstrap_token: str = Field(..., description="Short-lived bootstrap enrollment token")
    hostname: str = Field(..., description="Endpoint machine hostname")
    operating_system: str = Field(..., description="OS name and release")
    mac_address: str = Field(..., description="Primary network MAC address")
    machine_architecture: str = Field("x86_64", description="Host CPU architecture")
    tenant_id: str = Field("default", description="Target tenant identifier")


@router.get("", status_code=status.HTTP_200_OK)
async def list_agents():
    """List all agents currently or previously registered with the platform."""
    try:
        devices = ch_service.get_devices()
        return {"items": devices, "total": len(devices)}
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        return {"items": [], "total": 0}


@router.get("/tokens", status_code=status.HTTP_200_OK)
async def list_agent_tokens():
    """List all active and revoked agent enrollment tokens."""
    tokens = await agent_service.list_tokens()
    return {"items": tokens, "total": len(tokens)}


@router.post("/token", status_code=status.HTTP_201_CREATED)
async def create_agent_token(payload: GenerateTokenRequest = GenerateTokenRequest()):
    """Provision a new secure enrollment token for an agent."""
    token_data = await agent_service.generate_token(description=payload.description)
    return token_data


@router.post("/enroll", status_code=status.HTTP_200_OK)
async def enroll_agent(payload: AgentEnrollRequest):
    """
    Enroll an agent endpoint using a valid bootstrap token.
    Returns provisioned agent credentials (agent_id, tenant_id, agent_token).
    """
    enrollment = await agent_service.enroll_agent(
        bootstrap_token=payload.bootstrap_token,
        hostname=payload.hostname,
        operating_system=payload.operating_system,
        mac_address=payload.mac_address,
        machine_architecture=payload.machine_architecture,
        tenant_id=payload.tenant_id,
    )
    if not enrollment:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked bootstrap enrollment token.",
        )

    logger.info(f"Successfully enrolled new agent '{enrollment['agent_id']}' for host '{payload.hostname}'.")
    return {
        "status": "enrolled",
        "agent_id": enrollment["agent_id"],
        "tenant_id": enrollment["tenant_id"],
        "agent_token": enrollment["agent_token"],
        "enrolled_at": enrollment["enrolled_at"],
    }


@router.delete("/tokens/{token}", status_code=status.HTTP_200_OK)
async def revoke_agent_token(token: str):
    """Revoke an agent enrollment token to prevent further ingestion."""
    revoked = await agent_service.revoke_token(token)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Token not found or already revoked.",
        )
    return {"status": "success", "message": "Token successfully revoked."}
