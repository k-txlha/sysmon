"""
agent/enroll.py

Automated Enrollment Client and CLI for the Sysmon EDR Agent.
Performs secure bootstrapping handshake with the backend gateway, provisions
dedicated agent credentials, and configures the local agent environment.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import platform
import re
import socket
import sys
from typing import Any, Dict, Optional
import uuid
from urllib.parse import urlsplit

import requests

from agent.utils.logger import setup_logger
from agent.utils.config import settings
from agent.utils.token_manager import persist_agent_configuration

logger = setup_logger("agent_enroll")
BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def _get_mac_address() -> str:
    """Extracts host primary MAC address."""
    try:
        return ":".join(re.findall("..", "%012x" % uuid.getnode()))
    except Exception:
        return "00:00:00:00:00:00"


def _validate_backend_url(backend_url: str) -> None:
    parsed = urlsplit(backend_url)
    if parsed.scheme == "https":
        return
    try:
        local_address = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        local_address = (parsed.hostname or "").lower() == "localhost"
    if parsed.scheme != "http" or not local_address:
        raise ValueError("Agent enrollment requires HTTPS with certificate verification.")


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
    _ = tenant_id
    payload = {
        "bootstrap_token": bootstrap_token,
        "hostname": hostname,
        "operating_system": os_info,
        "mac_address": mac_addr,
        "machine_architecture": arch,
    }

    logger.info(f"Initiating enrollment handshake with backend at {endpoint}...")
    try:
        _validate_backend_url(backend_url)
        response = requests.post(endpoint, json=payload, timeout=10.0, verify=True)
        if response.status_code == 200:
            data = response.json()
            agent_token = data.get("agent_token")
            agent_id = data.get("agent_id")
            assigned_tenant_id = data.get("tenant_id")
            if not all(
                isinstance(value, str) and value
                for value in (agent_token, agent_id, assigned_tenant_id)
            ):
                raise ValueError("Enrollment response is missing assigned credentials or identity.")
            logger.info(f"Enrollment successful! Provisioned Agent ID: [{agent_id}]")

            # Persist to local .env
            _save_to_env(
                backend_url=f"{backend_url.rstrip('/')}/api/v1/telemetry",
                agent_token=agent_token,
                agent_id=agent_id,
                tenant_id=assigned_tenant_id,
            )
            settings.BACKEND_URL = f"{backend_url.rstrip('/')}/api/v1/telemetry"
            settings.AGENT_TOKEN = agent_token
            settings.AGENT_ID = agent_id
            settings.TENANT_ID = assigned_tenant_id
            return data
        elif response.status_code in [401, 403]:
            logger.critical(f"Enrollment rejected ({response.status_code}): Invalid or revoked bootstrap token.")
            return None
        else:
            logger.error(f"Enrollment failed with status {response.status_code}.")
            return None

    except (requests.exceptions.RequestException, ValueError) as e:
        logger.critical(f"Failed to connect to backend for enrollment: {e}")
        return None


def _save_to_env(
    backend_url: str,
    agent_token: str,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> None:
    """Updates or creates the local agent/.env file with provisioned credentials."""
    persist_agent_configuration(
        token_file=ENV_FILE,
        agent_token=agent_token,
        backend_url=backend_url,
        agent_id=agent_id,
        tenant_id=tenant_id,
    )

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
