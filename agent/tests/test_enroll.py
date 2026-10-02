"""
Tests for Agent Bootstrap Enrollment Client.
"""

from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import pytest

from enroll import enroll, _save_to_env, _get_mac_address


def test_get_mac_address():
    mac = _get_mac_address()
    assert isinstance(mac, str)
    assert len(mac.split(":")) == 6


def test_enroll_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "enrolled",
        "agent_id": "test-agent-01",
        "tenant_id": "default",
        "agent_token": "sysmon_agent_secret_token_123",
        "enrolled_at": "2026-10-02T12:00:00Z",
    }

    with patch("requests.post", return_value=mock_resp), patch("enroll._save_to_env") as mock_save:
        res = enroll(
            bootstrap_token="sysmon_tok_bootstrap_valid",
            backend_url="http://mock-backend:8000",
        )
        assert res is not None
        assert res["agent_id"] == "test-agent-01"
        assert res["agent_token"] == "sysmon_agent_secret_token_123"
        mock_save.assert_called_once_with(
            backend_url="http://mock-backend:8000/api/v1/telemetry",
            agent_token="sysmon_agent_secret_token_123",
        )


def test_enroll_invalid_token():
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Invalid bootstrap token"

    with patch("requests.post", return_value=mock_resp):
        res = enroll(
            bootstrap_token="sysmon_tok_invalid",
            backend_url="http://mock-backend:8000",
        )
        assert res is None


def test_save_to_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_env_file = Path(tmpdir) / ".env"
        with patch("enroll.ENV_FILE", temp_env_file):
            _save_to_env("http://backend:8000/api/v1/telemetry", "tok_xyz")

            content = temp_env_file.read_text()
            assert "SIEM_BACKEND_URL=http://backend:8000/api/v1/telemetry" in content
            assert "SIEM_AGENT_TOKEN=tok_xyz" in content
