"""
agent/utils/transport.py

Resilient Telemetry Transport for the Sysmon Agent.
Features local bounded SQLite disk queuing, exponential backoff with jitter,
and server acknowledgment to guarantee zero silent telemetry loss.
"""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

import requests

from agent.utils.buffer import LocalBoundedBuffer
from agent.utils.config import settings
from agent.utils.logger import setup_logger
from agent.utils.retry import retry_after_seconds
from agent.utils.token_manager import (
    get_current_token,
    is_authenticated,
    report_authentication_failure,
)

logger = setup_logger("transport")

# Singleton disk buffer instance
_buffer_instance: Optional[LocalBoundedBuffer] = None
_retry_lock = threading.Lock()
_retry_attempt = 0
_retry_at = 0.0
RETRY_BASE_SECONDS = 1.0
RETRY_MAX_SECONDS = 300.0


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
            retention_seconds=settings.BUFFER_RETENTION_SECONDS,
        )
    return _buffer_instance


def _schedule_retry(retry_after: Optional[str] = None) -> None:
    global _retry_attempt, _retry_at
    with _retry_lock:
        _retry_attempt += 1
        backoff = min(
            RETRY_BASE_SECONDS * (2 ** (_retry_attempt - 1)),
            RETRY_MAX_SECONDS,
        )
        jittered = random.uniform(backoff * 0.8, backoff * 1.2)
        server_delay = retry_after_seconds(retry_after)
        _retry_at = time.monotonic() + max(jittered, server_delay or 0.0)


def _reset_retry() -> None:
    global _retry_attempt, _retry_at
    with _retry_lock:
        _retry_attempt = 0
        _retry_at = 0.0


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

    if not get_current_token():
        raise AgentAuthenticationError("Agent credential is not configured.")
    if not is_authenticated():
        return False

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
            expected_ids = [event.get("event_id") for event in events]
            try:
                acknowledgement = response.json()
            except (ValueError, AttributeError):
                acknowledgement = None
            if (
                not isinstance(acknowledgement, dict)
                or acknowledgement.get("status") != "accepted"
                or acknowledgement.get("ingested_count") != len(events)
                or acknowledgement.get("accepted_event_ids") != expected_ids
            ):
                logger.error(
                    "Backend response did not contain a valid acknowledgement for "
                    "the submitted event IDs; retaining events in the local buffer."
                )
                _schedule_retry()
                return False
            _reset_retry()
            logger.debug(f"Successfully transmitted {len(events)} event(s) to backend.")
            return True

        elif response.status_code == 429:
            _schedule_retry(response.headers.get("Retry-After"))
            logger.warning(
                "Backend rate limit (429) hit. Events remain queued for retry."
            )
            return False

        elif response.status_code in [401, 403]:
            report_authentication_failure()
            logger.critical(
                "Backend rejected the agent credential (%s); telemetry transmission "
                "is disabled until authentication succeeds.",
                response.status_code,
            )
            raise AgentAuthenticationError(
                f"Backend rejected agent authentication ({response.status_code})."
            )

        else:
            _schedule_retry(response.headers.get("Retry-After"))
            logger.error(
                "Backend returned HTTP %s; events remain queued for retry.",
                response.status_code,
            )
            return False

    except requests.exceptions.RequestException as e:
        _schedule_retry()
        logger.warning(
            "Telemetry delivery failed with %s; events remain queued for retry.",
            type(e).__name__,
        )
        return False


def drain_buffer(batch_size: int = 50, max_batches: int = 10) -> int:
    """
    Attempts to drain queued events from the local disk buffer in FIFO order.
    Returns the total number of events successfully transmitted and acknowledged.
    """
    buffer = get_buffer()
    total_drained = 0

    if not is_authenticated():
        return 0
    with _retry_lock:
        if time.monotonic() < _retry_at:
            return 0

    for _ in range(max_batches):
        pending_items = buffer.peek_batch(batch_size=batch_size)
        if not pending_items:
            break

        row_ids = [item[0] for item in pending_items]
        events = [item[1] for item in pending_items]

        try:
            success = send_batch_to_backend(events)
        except AgentAuthenticationError:
            break
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
