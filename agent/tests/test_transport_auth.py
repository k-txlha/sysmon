from unittest.mock import MagicMock, patch

import pytest

from agent.utils import transport
from agent.utils.transport import AgentAuthenticationError


def test_transport_does_not_send_without_agent_credential():
    with patch("agent.utils.transport.get_current_token", return_value=""):
        with pytest.raises(AgentAuthenticationError):
            transport._get_headers()


def test_backend_authentication_rejection_stops_telemetry():
    response = MagicMock(status_code=401)
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.requests.post", return_value=response),
    ):
        with pytest.raises(AgentAuthenticationError):
            transport.send_batch_to_backend([{"agent_id": "agent_test"}])


def test_transport_rejects_plain_http_remote_backend():
    with (
        patch.object(transport.settings, "AGENT_ID", "agent_test"),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch.object(transport.settings, "BACKEND_URL", "http://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.requests.post") as post,
    ):
        with pytest.raises(ValueError, match="requires HTTPS"):
            transport.send_batch_to_backend([{"agent_id": "agent_test"}])
    post.assert_not_called()


def test_queued_events_are_bound_to_enrolled_identity():
    response = MagicMock(status_code=202)
    event = {"agent_id": "old-host-id", "tenant_id": "old-tenant"}
    with (
        patch.object(transport.settings, "AGENT_ID", "backend-agent-id"),
        patch.object(transport.settings, "TENANT_ID", "backend-tenant-id"),
        patch.object(transport.settings, "BACKEND_URL", "https://backend.example/api/v1/telemetry"),
        patch("agent.utils.transport.get_current_token", return_value="present"),
        patch("agent.utils.transport.requests.post", return_value=response) as post,
    ):
        assert transport.send_batch_to_backend([event])
    assert event == {
        "agent_id": "backend-agent-id",
        "tenant_id": "backend-tenant-id",
    }
    assert post.call_args.kwargs["json"] == event


def test_transport_does_not_send_without_enrolled_identity():
    with (
        patch.object(transport.settings, "AGENT_ID", ""),
        patch.object(transport.settings, "TENANT_ID", "default"),
        patch("agent.utils.transport.requests.post") as post,
    ):
        with pytest.raises(AgentAuthenticationError, match="identities"):
            transport.send_batch_to_backend([{"agent_id": "agent_test"}])
    post.assert_not_called()
