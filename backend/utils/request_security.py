"""Transport security checks for agent-facing endpoints."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from backend.config.settings import settings


def uses_secure_agent_transport(request: Request) -> bool:
    """Allow HTTPS, plus loopback HTTP exclusively for non-production development."""
    if request.url.scheme == "https":
        return True
    if settings.ENVIRONMENT == "production":
        return False
    client_host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return False
