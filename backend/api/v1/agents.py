"""
backend/api/v1/agents.py

REST API router for Agent Management:
- Enumerate connected and registered telemetry agents
- Provision and manage agent enrollment API tokens
- Agent enrollment handshake endpoint
- Token validation and revocation
"""

from __future__ import annotations

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from backend.services.agent_service import agent_service
from backend.api.v1.auth import require_admin
from backend.services.ch_service import ch_service
from backend.utils.logger import setup_logger
from backend.utils.request_security import uses_secure_agent_transport

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
    tenant_id: str = Field(
        "default",
        description="Deprecated and ignored; tenant identity is assigned by the backend.",
    )


@router.get("", status_code=status.HTTP_200_OK, dependencies=[Depends(require_admin)])
async def list_agents():
    """List all agents currently or previously registered with the platform."""
    try:
        devices = ch_service.get_devices()
        return {"items": devices, "total": len(devices)}
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        return {"items": [], "total": 0}


@router.get("/tokens", status_code=status.HTTP_200_OK, dependencies=[Depends(require_admin)])
async def list_agent_tokens():
    """List all active and revoked agent enrollment tokens."""
    tokens = await agent_service.list_tokens()
    return {"items": tokens, "total": len(tokens)}


@router.post(
    "/token",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
async def create_agent_token(
    response: Response,
    payload: GenerateTokenRequest = GenerateTokenRequest(),
):
    """Provision a new secure enrollment token for an agent."""
    response.headers["Cache-Control"] = "no-store"
    token_data = await agent_service.generate_token(description=payload.description)
    return token_data


@router.post("/enroll", status_code=status.HTTP_200_OK)
async def enroll_agent(
    payload: AgentEnrollRequest,
    request: Request,
    response: Response,
):
    """
    Enroll an agent endpoint using a valid bootstrap token.
    Returns provisioned agent credentials (agent_id, tenant_id, agent_token).
    """
    if not uses_secure_agent_transport(request):
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail="Agent enrollment requires HTTPS with certificate verification.",
        )

    response.headers["Cache-Control"] = "no-store"
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
        "expires_at": enrollment["expires_at"],
    }


@router.post("/renew", status_code=status.HTTP_200_OK)
async def renew_agent_token(
    request: Request,
    response: Response,
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(default=None),
):
    """Validate and rotate the current credential for an enrolled agent."""
    if not uses_secure_agent_transport(request):
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail="Agent credential renewal requires HTTPS.",
        )
    response.headers["Cache-Control"] = "no-store"
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

    token_data = await agent_service.renew_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid, expired, revoked, or inactive agent token.",
        )

    return {
        "agent_token": token_data["token"],
        "agent_id": token_data["agent_id"],
        "expires_at": token_data["expiration"],
        "renewed": token_data.get("renewed", True),
    }


@router.delete(
    "/tokens/{credential_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_admin)],
)
async def revoke_agent_token(credential_id: UUID):
    """Revoke a credential by its opaque administrator-facing record ID."""
    revoked = await agent_service.revoke_token(str(credential_id))
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found or already revoked.",
        )
    return {"status": "success", "message": "Token successfully revoked."}
