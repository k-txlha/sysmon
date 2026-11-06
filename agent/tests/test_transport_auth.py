from unittest.mock import MagicMock, patch

import pytest

from agent.utils import transport
from agent.utils.transport import AgentAuthenticationError


def _ack_response(event_ids):
    response = MagicMock(status_code=202)
    response.headers = {}
    response.json.return_value = {
        "status": "accepted",
        "ingested_count": len(event_ids),
        "accepted_event_ids": event_ids,
    }
    return response


def test_transport_does_not_send_without_agent_credential():
    with patch("agent.utils.transport.get_current_token", return_value=""):
        with pytest.raises(AgentAuthenticationError):
            transport._get_headers()


@pytest.mark.parametrize("status_code", [401, 403])
def test_backend_authentication_rejection_disables_telemetry(status_code, caplog):
    response = MagicMock(status_code=status_code)
    response.json.return_value = {"detail": "sensitive-token-must-not-be-logged"}
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.report_authentication_failure") as auth_failed,
        patch("agent.utils.transport.requests.post", return_value=response),
    ):
        with pytest.raises(AgentAuthenticationError):
            transport.send_batch_to_backend([{"event_id": "evt-1"}])
    auth_failed.assert_called_once()
    assert "sensitive-token-must-not-be-logged" not in caplog.text


def test_transport_rejects_plain_http_remote_backend():
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "http://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.requests.post") as post,
    ):
        with pytest.raises(ValueError, match="requires HTTPS"):
            transport.send_batch_to_backend([{"event_id": "evt-1"}])
    post.assert_not_called()


def test_queued_events_are_bound_to_enrolled_identity():
    response = _ack_response(["evt-1"])
    event = {
        "event_id": "evt-1",
        "agent_id": "old-host-id",
        "tenant_id": "old-tenant",
    }
    with (
        patch.object(transport.settings, "AGENT_ID", "backend-agent-id"),
        patch.object(transport.settings, "TENANT_ID", "backend-tenant-id"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.requests.post", return_value=response) as post,
    ):
        assert transport.send_batch_to_backend([event])
    sent_event = post.call_args.kwargs["json"]
    assert event == {
        "event_id": "evt-1",
        "agent_id": "backend-agent-id",
        "tenant_id": "backend-tenant-id",
    }
    assert sent_event["event_id"] == "evt-1"
    assert sent_event["agent_id"] == "backend-agent-id"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer present"


def test_transport_does_not_send_without_enrolled_identity():
    with (
        patch.object(transport.settings, "AGENT_ID", ""),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.requests.post") as post,
    ):
        with pytest.raises(AgentAuthenticationError, match="identities"):
            transport.send_batch_to_backend([{"event_id": "evt-1"}])
    post.assert_not_called()


def test_unconfirmed_authentication_never_transmits():
    with (
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=False),
        patch("agent.utils.transport.requests.post") as post,
    ):
        assert not transport.send_batch_to_backend([{"event_id": "evt-1"}])
    post.assert_not_called()


def test_ship_buffers_events_before_authentication_succeeds():
    buffer = MagicMock()
    with (
        patch("agent.utils.transport.get_buffer", return_value=buffer),
        patch("agent.utils.transport.is_authenticated", return_value=False),
        patch("agent.utils.transport.drain_buffer", return_value=0) as drain,
    ):
        assert not transport.ship_to_backend({"event_id": "evt-offline"})
    buffer.push.assert_called_once_with({"event_id": "evt-offline"})
    drain.assert_called_once()


def test_invalid_acknowledgement_keeps_batch_pending():
    response = _ack_response(["different-event"])
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.requests.post", return_value=response),
    ):
        assert not transport.send_batch_to_backend([{"event_id": "evt-1"}])


def test_rate_limit_retry_after_is_honored():
    response = MagicMock(status_code=429)
    response.headers = {"Retry-After": "30"}
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.requests.post", return_value=response),
        patch("agent.utils.transport.time.monotonic", return_value=100.0),
        patch("agent.utils.transport.random.uniform", return_value=0.8),
    ):
        transport._reset_retry()
        assert not transport.send_batch_to_backend([{"event_id": "evt-1"}])
        assert transport._retry_at == 130.0
    transport._reset_retry()


def test_drain_removes_events_only_after_valid_acknowledgement():
    pending = [(7, {"event_id": "evt-1"})]
    buffer = MagicMock()
    buffer.peek_batch.return_value = pending
    with (
        patch("agent.utils.transport.get_buffer", return_value=buffer),
        patch("agent.utils.transport.is_authenticated", return_value=True),
        patch("agent.utils.transport.send_batch_to_backend", return_value=False),
    ):
        assert transport.drain_buffer() == 0
    buffer.pop_batch.assert_not_called()
