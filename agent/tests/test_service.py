"""
Tests for Agent Service Lifecycle Manager.
"""

from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest

from service import (
    LinuxServiceManager,
    WindowsServiceManager,
    get_service_manager,
    _get_systemd_unit_content,
)


def test_systemd_unit_generation():
    unit = _get_systemd_unit_content()
    assert "[Unit]" in unit
    assert "Description=Sysmon EDR Telemetry Agent" in unit
    assert "[Service]" in unit
    assert "Restart=always" in unit
    assert "ExecStart=" in unit


def test_get_service_manager_platform_dispatch():
    with patch("platform.system", return_value="Linux"):
        mgr = get_service_manager()
        assert mgr == LinuxServiceManager

    with patch("platform.system", return_value="Windows"):
        mgr = get_service_manager()
        assert mgr == WindowsServiceManager


def test_linux_service_manager_status():
    mock_path = MagicMock()
    mock_path.exists.return_value = True

    with patch("subprocess.run") as mock_run, patch.object(LinuxServiceManager, "UNIT_PATH", mock_path):
        mock_run.return_value = MagicMock(return_value=0, stdout="active\n", returncode=0)
        status = LinuxServiceManager.status()
        assert status["platform"] == "linux"
        assert status["installed"] is True
        assert status["active"] is True


def test_windows_service_manager_status():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Status: Running\n")
        status = WindowsServiceManager.status()
        assert status["platform"] == "windows"
        assert status["installed"] is True
        assert status["active"] is True
