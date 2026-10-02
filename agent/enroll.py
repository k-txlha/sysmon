"""
agent/enroll.py

Automated Enrollment Client and CLI for the Sysmon EDR Agent.
Performs secure bootstrapping handshake with the backend gateway, provisions
dedicated agent credentials, and configures the local agent environment.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import platform
import re
import socket
import sys
from typing import Any, Dict, Optional
import uuid

import requests

from utils.logger import setup_logger

logger = setup_logger("agent_enroll")
BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def _get_mac_address() -> str:
    """Extracts host primary MAC address."""
    try:
        return ":".join(re.findall("..", "%012x" % uuid.getnode()))
    except Exception:
        return "00:00:00:00:00:00"


def enroll(
    bootstrap_token: str,
    backend_url: str = "http://127.0.0.1:8000",
    tenant_id: str = "default",
) -> Optional[Dict[str, Any]]:
    """
    Executes the enrollment handshake against the Sysmon Backend Gateway.
    Saves the returned agent token and configurations to agent/.env upon success.
    """
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"
    mac_addr = _get_mac_address()
    arch = platform.machine()

    endpoint = f"{backend_url.rstrip('/')}/api/v1/agents/enroll"
    payload = {
        "bootstrap_token": bootstrap_token,
        "hostname": hostname,
        "operating_system": os_info,
        "mac_address": mac_addr,
        "machine_architecture": arch,
        "tenant_id": tenant_id,
    }

    logger.info(f"Initiating enrollment handshake with backend at {endpoint}...")
    try:
        response = requests.post(endpoint, json=payload, timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            agent_token = data.get("agent_token")
            agent_id = data.get("agent_id")
            logger.info(f"Enrollment successful! Provisioned Agent ID: [{agent_id}]")

            # Persist to local .env
            _save_to_env(
                backend_url=f"{backend_url.rstrip('/')}/api/v1/telemetry",
                agent_token=agent_token,
            )
            return data
        elif response.status_code in [401, 403]:
            logger.critical(f"Enrollment rejected ({response.status_code}): Invalid or revoked bootstrap token.")
            return None
        else:
            logger.error(f"Enrollment failed ({response.status_code}): {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.critical(f"Failed to connect to backend for enrollment: {e}")
        return None


def _save_to_env(backend_url: str, agent_token: str) -> None:
    """Updates or creates the local agent/.env file with provisioned credentials."""
    env_vars = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip()

    env_vars["SIEM_BACKEND_URL"] = backend_url
    env_vars["SIEM_AGENT_TOKEN"] = agent_token

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write("# Sysmon Agent Configuration\n")
        for k, v in env_vars.items():
            f.write(f"{k}={v}\n")

    logger.info(f"Updated configuration saved to {ENV_FILE}")


def main():
    parser = argparse.ArgumentParser(
        description="Sysmon EDR Agent Bootstrap Enrollment CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Bootstrap enrollment token generated from the Sysmon backend/dashboard",
    )
    parser.add_argument(
        "--backend",
        default="http://127.0.0.1:8000",
        help="Backend gateway base URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--tenant",
        default="default",
        help="Target tenant ID (default: default)",
    )
    args = parser.parse_args()

    result = enroll(
        bootstrap_token=args.token,
        backend_url=args.backend,
        tenant_id=args.tenant,
    )
    if result:
        print("\n [SUCCESS] Agent successfully enrolled and ready to run.")
        sys.exit(0)
    else:
        print("\n [ERROR] Agent enrollment failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
