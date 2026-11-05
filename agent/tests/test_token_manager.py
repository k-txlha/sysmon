from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.utils import token_manager
from agent.utils.token_manager import AgentTokenManager


def _renewal_response(agent_token: str) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "agent_token": agent_token,
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
        headers={"X-Agent-Token": "old-token"},
        timeout=10.0,
    )


def test_persistence_failure_keeps_current_token(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SIEM_AGENT_TOKEN=old-token\n", encoding="utf-8")
    manager = AgentTokenManager(
        token="old-token",
        backend_url="http://backend/api/v1/telemetry",
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
