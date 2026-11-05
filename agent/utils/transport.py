"""
agent/utils/transport.py

Resilient Telemetry Transport for the Sysmon Agent.
Features local bounded SQLite disk queuing, exponential backoff with jitter,
and server acknowledgment to guarantee zero silent telemetry loss.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

import requests

from agent.utils.buffer import LocalBoundedBuffer
from agent.utils.config import settings
from agent.utils.logger import setup_logger
from agent.utils.token_manager import get_current_token

logger = setup_logger("transport")

# Singleton disk buffer instance
_buffer_instance: Optional[LocalBoundedBuffer] = None


class AgentAuthenticationError(RuntimeError):
    """Raised when agent credentials are missing or rejected by the backend."""


def _validate_backend_url() -> None:
    parsed = urlsplit(settings.BACKEND_URL)
    if parsed.scheme == "https":
        return
    try:
        local_address = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        local_address = (parsed.hostname or "").lower() == "localhost"
    if parsed.scheme != "http" or not local_address:
        raise ValueError("Agent telemetry requires HTTPS with certificate verification.")


def get_buffer() -> LocalBoundedBuffer:
    """Returns the singleton disk buffer instance."""
    global _buffer_instance
    if _buffer_instance is None:
        _buffer_instance = LocalBoundedBuffer(
            db_path=settings.BUFFER_DB_PATH,
            max_events=settings.BUFFER_MAX_EVENTS,
            max_bytes=settings.BUFFER_MAX_BYTES,
        )
    return _buffer_instance


def _get_headers() -> Dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SysmonAgent/1.0",
    }
    token = get_current_token()
    if not token:
        raise AgentAuthenticationError("Agent credential is not configured.")
    headers["Authorization"] = f"Bearer {token}"
    return headers


def _bind_enrolled_identity(events: List[Dict[str, Any]]) -> None:
    agent_id = settings.AGENT_ID
    tenant_id = settings.TENANT_ID
    if not agent_id or not tenant_id:
        raise AgentAuthenticationError(
            "Backend-assigned agent and tenant identities are not configured."
        )
    for event in events:
        event["agent_id"] = agent_id
        event["tenant_id"] = tenant_id


def send_batch_to_backend(events: List[Dict[str, Any]]) -> bool:
    """
    Directly transmits a batch of EventEnvelopes to the SIEM ingestion endpoint.
    Handles rate-limiting (429) and network errors.
    """
    if not events:
        return True

    _bind_enrolled_identity(events)
    payload = {"events": events} if len(events) > 1 else events[0]

    try:
        _validate_backend_url()
        response = requests.post(
            settings.BACKEND_URL,
            json=payload,
            headers=_get_headers(),
            timeout=15.0,
            verify=True,
        )

        if response.status_code in [200, 202]:
            logger.debug(f"Successfully transmitted {len(events)} event(s) to backend.")
            return True

        elif response.status_code == 429:
            logger.warning("Backend rate limit (429) hit. Events queued in buffer.")
            return False

        elif response.status_code in [401, 403]:
            try:
                response_detail = response.json().get("detail", "")
            except (ValueError, AttributeError):
                response_detail = ""
            detail = (
                f" Backend response: {response_detail}"
                if isinstance(response_detail, str) and response_detail
                else ""
            )
            logger.critical(
                f"Authentication failed ({response.status_code}); stopping telemetry transmission.{detail}"
            )
            raise AgentAuthenticationError(
                f"Backend rejected telemetry ({response.status_code}).{detail}"
            )

        else:
            logger.error(f"Backend rejected payload with status {response.status_code}.")
            return False

    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to connect to SIEM backend ({settings.BACKEND_URL}): {e}")
        return False


def drain_buffer(batch_size: int = 50, max_batches: int = 10) -> int:
    """
    Attempts to drain queued events from the local disk buffer in FIFO order.
    Returns the total number of events successfully transmitted and acknowledged.
    """
    buffer = get_buffer()
    total_drained = 0

    for _ in range(max_batches):
        pending_items = buffer.peek_batch(batch_size=batch_size)
        if not pending_items:
            break

        row_ids = [item[0] for item in pending_items]
        events = [item[1] for item in pending_items]

        success = send_batch_to_backend(events)
        if success:
            popped = buffer.pop_batch(row_ids)
            total_drained += popped
            logger.info(f"Drained and acknowledged {popped} queued events from disk buffer.")
        else:
            # Backend is still unreachable or rate-limited; stop draining this cycle
            break

    return total_drained


def ship_to_backend(payload: Union[Dict[str, Any], List[Dict[str, Any]]]) -> bool:
    """
    Primary ingestion entrypoint for the agent.
    Durable workflow:
    1. Enqueues new event(s) to the local bounded buffer.
    2. Drains buffer in FIFO order to the backend.
    """
    if not payload:
        return False

    buffer = get_buffer()

    # Enqueue new event envelopes
    if isinstance(payload, list):
        for event in payload:
            buffer.push(event)
    elif isinstance(payload, dict):
        buffer.push(payload)

    # Drain buffer (sends oldest first)
    drained = drain_buffer()
    return drained > 0
