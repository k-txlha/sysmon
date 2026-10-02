"""
agent/service.py

Cross-platform OS service lifecycle manager for the Sysmon EDR Agent.
Supports installation, uninstallation, starting, stopping, and status checks
on Linux (systemd) and Windows (Service / Background task).
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger("agent_service_mgr")

BASE_DIR = Path(__file__).resolve().parent
MAIN_SCRIPT = BASE_DIR / "main.py"
PYTHON_EXE = sys.executable
SERVICE_NAME = "sysmon-agent"
SERVICE_DISPLAY_NAME = "Sysmon EDR Telemetry Agent"
SERVICE_DESCRIPTION = "Continuous endpoint telemetry and security audit collector for Sysmon EDR."


def _get_systemd_unit_content() -> str:
    """Generates a standard systemd service unit file content."""
    return f"""[Unit]
Description={SERVICE_DISPLAY_NAME}
Documentation=https://github.com/sysmon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={BASE_DIR}
ExecStart={PYTHON_EXE} {MAIN_SCRIPT}
Restart=always
RestartSec=10
KillMode=process
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""


class LinuxServiceManager:
    """Manages systemd service lifecycle on Linux distributions."""

    UNIT_PATH = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"

    @classmethod
    def install(cls) -> bool:
        if os.geteuid() != 0:
            logger.error("Root privileges required to install systemd service. Run with sudo.")
            return False

        try:
            content = _get_systemd_unit_content()
            cls.UNIT_PATH.write_text(content, encoding="utf-8")
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True)
            logger.info(f"Successfully installed and enabled {SERVICE_NAME} service at {cls.UNIT_PATH}")
            return True
        except Exception as e:
            logger.error(f"Failed to install systemd service: {e}")
            return False

    @classmethod
    def uninstall(cls) -> bool:
        if os.geteuid() != 0:
            logger.error("Root privileges required to uninstall systemd service. Run with sudo.")
            return False

        try:
            subprocess.run(["systemctl", "stop", SERVICE_NAME], check=False)
            subprocess.run(["systemctl", "disable", SERVICE_NAME], check=False)
            if cls.UNIT_PATH.exists():
                cls.UNIT_PATH.unlink()
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            logger.info(f"Successfully uninstalled {SERVICE_NAME} service.")
            return True
        except Exception as e:
            logger.error(f"Failed to uninstall systemd service: {e}")
            return False

    @classmethod
    def start(cls) -> bool:
        try:
            res = subprocess.run(["systemctl", "start", SERVICE_NAME], capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Service {SERVICE_NAME} started successfully.")
                return True
            logger.error(f"Failed to start service: {res.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Error starting service: {e}")
            return False

    @classmethod
    def stop(cls) -> bool:
        try:
            res = subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Service {SERVICE_NAME} stopped.")
                return True
            logger.error(f"Failed to stop service: {res.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Error stopping service: {e}")
            return False

    @classmethod
    def status(cls) -> dict:
        try:
            res = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
            active_state = res.stdout.strip()
            installed = cls.UNIT_PATH.exists()
            return {
                "service_name": SERVICE_NAME,
                "platform": "linux",
                "installed": installed,
                "status": active_state if installed else "not_installed",
                "active": active_state == "active",
            }
        except Exception as e:
            return {"service_name": SERVICE_NAME, "platform": "linux", "error": str(e)}


class WindowsServiceManager:
    """Manages Windows service / background task lifecycle."""

    @classmethod
    def install(cls) -> bool:
        """Registers a Windows background scheduled task with automatic startup on boot."""
        try:
            cmd = [
                "schtasks",
                "/Create",
                "/F",
                "/SC", "ONSTART",
                "/TN", SERVICE_NAME,
                "/TR", f'"{PYTHON_EXE}" "{MAIN_SCRIPT}"',
                "/RL", "HIGHEST",
                "/RU", "SYSTEM",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Successfully registered {SERVICE_DISPLAY_NAME} on Windows startup.")
                return True
            logger.error(f"Failed to register Windows task: {res.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Error installing Windows service task: {e}")
            return False

    @classmethod
    def uninstall(cls) -> bool:
        try:
            cmd = ["schtasks", "/Delete", "/TN", SERVICE_NAME, "/F"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Successfully removed {SERVICE_DISPLAY_NAME} from Windows tasks.")
                return True
            logger.warning(f"Task delete response: {res.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Error uninstalling Windows service task: {e}")
            return False

    @classmethod
    def start(cls) -> bool:
        try:
            cmd = ["schtasks", "/Run", "/TN", SERVICE_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Successfully triggered {SERVICE_NAME} to run.")
                return True
            logger.error(f"Failed to start task: {res.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Error starting task: {e}")
            return False

    @classmethod
    def stop(cls) -> bool:
        try:
            cmd = ["schtasks", "/End", "/TN", SERVICE_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                logger.info(f"Stopped {SERVICE_NAME} task.")
                return True
            return False
        except Exception as e:
            logger.error(f"Error stopping task: {e}")
            return False

    @classmethod
    def status(cls) -> dict:
        try:
            cmd = ["schtasks", "/Query", "/TN", SERVICE_NAME, "/FO", "LIST"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            installed = res.returncode == 0
            is_running = "Running" in res.stdout
            return {
                "service_name": SERVICE_NAME,
                "platform": "windows",
                "installed": installed,
                "status": "running" if is_running else ("ready" if installed else "not_installed"),
                "active": is_running,
            }
        except Exception as e:
            return {"service_name": SERVICE_NAME, "platform": "windows", "error": str(e)}


def get_service_manager():
    """Returns the appropriate service manager for the host OS."""
    os_name = platform.system().lower()
    if os_name == "linux":
        return LinuxServiceManager
    elif os_name == "windows":
        return WindowsServiceManager
    else:
        raise NotImplementedError(f"Service management not supported on OS: {os_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Sysmon EDR Agent Service Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "action",
        choices=["install", "uninstall", "start", "stop", "status"],
        help="Service action to perform",
    )
    args = parser.parse_args()

    try:
        manager = get_service_manager()
    except NotImplementedError as err:
        logger.error(str(err))
        sys.exit(1)

    action_map = {
        "install": manager.install,
        "uninstall": manager.uninstall,
        "start": manager.start,
        "stop": manager.stop,
        "status": lambda: print(manager.status()),
    }

    result = action_map[args.action]()
    if isinstance(result, bool):
        sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
