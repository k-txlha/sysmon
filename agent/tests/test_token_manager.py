from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.utils import token_manager
from agent.utils.token_manager import AgentTokenManager


def _renewal_response(agent_token: str) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "agent_token": agent_token,
        "agent_id": token_manager.settings.AGENT_ID or "agent-test",
        "tenant_id": token_manager.settings.TENANT_ID,
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "renewed": True,
    }
    return response


def test_renewal_persists_replacement_before_switching_token(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SIEM_AGENT_TOKEN=old-token\nCUSTOM_SETTING=value\n", encoding="utf-8")
    manager = AgentTokenManager(
        token="old-token",
        backend_url="https://backend.example/api/v1/telemetry",
        token_file=env_file,
    )
    monkeypatch.setattr(token_manager.settings, "AGENT_TOKEN", "old-token")
    response = _renewal_response("new-token")

    with patch("agent.utils.token_manager.requests.post", return_value=response) as post:
        delay = manager._renew_once()

    assert manager.current_token == "new-token"
    assert "SIEM_AGENT_TOKEN=new-token" in env_file.read_text(encoding="utf-8")
    assert "CUSTOM_SETTING=value" in env_file.read_text(encoding="utf-8")
    assert delay > 0
    post.assert_called_once_with(
        "https://backend.example/api/v1/agents/renew",
        headers={"Authorization": "Bearer old-token"},
        timeout=10.0,
        verify=True,
    )


def test_persistence_failure_keeps_current_token(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SIEM_AGENT_TOKEN=old-token\n", encoding="utf-8")
    manager = AgentTokenManager(
        token="old-token",
        backend_url="https://backend.example/api/v1/telemetry",
        token_file=env_file,
    )
    response = _renewal_response("new-token")
    monkeypatch.setattr(
        token_manager,
        "persist_agent_configuration",
        MagicMock(side_effect=OSError("disk unavailable")),
    )

    with patch("agent.utils.token_manager.requests.post", return_value=response):
        with pytest.raises(OSError, match="disk unavailable"):
            manager._renew_once()

    assert manager.current_token == "old-token"
    assert "SIEM_AGENT_TOKEN=old-token" in env_file.read_text(encoding="utf-8")


def test_renewal_authentication_rejection_disables_authenticated_mode(tmp_path: Path):
    manager = AgentTokenManager(
        token="old-token",
        backend_url="https://backend.example/api/v1/telemetry",
        token_file=tmp_path / ".env",
    )
    unauthorized = requests.HTTPError(
        "unauthorized",
        response=MagicMock(status_code=401),
    )
    waits = 0

    def wait_then_stop(_delay):
        nonlocal waits
        waits += 1
        if waits > 1:
            manager._stop_event.set()
            return True
        return False

    with patch(
        "agent.utils.token_manager.requests.post",
        side_effect=unauthorized,
    ), patch.object(manager._wake_event, "wait", side_effect=wait_then_stop):
        manager._renewal_loop()
    assert manager.authentication_failed
    assert not manager.authenticated


def test_temporary_outage_preserves_token_and_retries(tmp_path: Path):
    env_file = tmp_path / ".env"
    manager = AgentTokenManager(
        token="old-token",
        backend_url="https://backend.example/api/v1/telemetry",
        token_file=env_file,
    )
    waits = 0

    def wait_then_stop(_delay):
        nonlocal waits
        waits += 1
        if waits > 1:
            manager._stop_event.set()
            return True
        return False

    with patch(
        "agent.utils.token_manager.requests.post",
        side_effect=requests.ConnectionError("backend unavailable"),
    ), patch.object(manager._wake_event, "wait", side_effect=wait_then_stop):
        manager._renewal_loop()

    assert manager.current_token == "old-token"
    assert not env_file.exists()
    assert not manager.authenticated
    assert not manager.authentication_failed


def test_successful_renewal_enables_authenticated_mode(tmp_path: Path):
    manager = AgentTokenManager(
        token="old-token",
        backend_url="https://backend.example/api/v1/telemetry",
        token_file=tmp_path / ".env",
    )
    response = _renewal_response("old-token")
    waits = 0

    def wait_then_stop(_delay):
        nonlocal waits
        waits += 1
        if waits > 1:
            manager._stop_event.set()
            return True
        return False

    with patch(
        "agent.utils.token_manager.requests.post", return_value=response
    ), patch.object(manager._wake_event, "wait", side_effect=wait_then_stop):
        manager._renewal_loop()

    assert manager.authenticated
    assert not manager.authentication_failed
