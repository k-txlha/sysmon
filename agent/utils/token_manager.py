"""Background renewal and durable persistence for the agent credential."""

from __future__ import annotations

import os
import random
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from agent.utils.config import ENV_FILE_PATH, settings
from agent.utils.logger import setup_logger
from agent.utils.retry import retry_after_seconds

logger = setup_logger("token_manager")
RENEWAL_MARGIN = timedelta(minutes=5)
RETRY_BASE_SECONDS = 5
RETRY_MAX_SECONDS = 300


def persist_agent_configuration(
    token_file: Path,
    agent_token: str,
    backend_url: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> None:
    """Atomically persist updated agent credentials in the existing env file."""
    values = {"SIEM_AGENT_TOKEN": agent_token}
    if backend_url is not None:
        values["SIEM_BACKEND_URL"] = backend_url
    if agent_id is not None:
        values["SIEM_AGENT_ID"] = agent_id
    if tenant_id is not None:
        values["SIEM_TENANT_ID"] = tenant_id

    existing_lines = (
        token_file.read_text(encoding="utf-8").splitlines()
        if token_file.exists()
        else []
    )
    updated_lines = []
    written = set()
    for line in existing_lines:
        key, separator, _ = line.partition("=")
        normalized_key = key.strip()
        if separator and normalized_key in values:
            if normalized_key not in written:
                updated_lines.append(f"{normalized_key}={values[normalized_key]}")
                written.add(normalized_key)
        else:
            updated_lines.append(line)
    for key, value in values.items():
        if key not in written:
            updated_lines.append(f"{key}={value}")

    temporary_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=token_file.parent,
            prefix=f".{token_file.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            temporary_file.write("\n".join(updated_lines) + "\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        if temporary_path is None:
            raise OSError("Temporary credential file was not created.")
        if os.name == "nt":
            identity = subprocess.run(
                ["whoami"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "icacls",
                    temporary_path,
                    "/inheritance:r",
                    "/grant:r",
                    f"{identity}:(F)",
                    "SYSTEM:(F)",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, token_file)
    except (OSError, subprocess.SubprocessError):
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
        raise


class AgentTokenManager:
    def __init__(
        self,
        token: Optional[str] = None,
        backend_url: Optional[str] = None,
        token_file: Path = ENV_FILE_PATH,
    ) -> None:
        self._token = token if token is not None else settings.AGENT_TOKEN
        self._backend_url = (
            backend_url if backend_url is not None else settings.BACKEND_URL
        )
        self._token_file = token_file
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._authentication_failed = threading.Event()
        self._authenticated = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def current_token(self) -> str:
        with self._lock:
            return self._token

    @property
    def authentication_failed(self) -> bool:
        return self._authentication_failed.is_set()

    @property
    def authenticated(self) -> bool:
        return self._authenticated.is_set() and not self._authentication_failed.is_set()

    def report_authentication_failure(self) -> None:
        self._authenticated.clear()
        self._authentication_failed.set()
        self._wake_event.set()

    def start(self) -> None:
        with self._lock:
            if not self._token:
                logger.warning("Agent token is not configured; background renewal was not started.")
                return
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._wake_event.clear()
            self._authentication_failed.clear()
            self._authenticated.clear()
            self._thread = threading.Thread(
                target=self._renewal_loop,
                name="agent-token-renewal",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=10)

    def _renewal_url(self) -> str:
        parsed = urlsplit(self._backend_url)
        path = parsed.path.rstrip("/")
        if path.endswith("/telemetry"):
            path = path[: -len("/telemetry")]
        renewal_path = f"{path}/agents/renew"
        return urlunsplit(
            (parsed.scheme, parsed.netloc, renewal_path, parsed.query, parsed.fragment)
        )

    def _persist_replacement(self, new_token: str) -> None:
        persist_agent_configuration(self._token_file, new_token)
        with self._lock:
            self._token = new_token
            settings.AGENT_TOKEN = new_token

    def _renew_once(self) -> float:
        token = self.current_token
        renewal_url = self._renewal_url()
        parsed_url = urlsplit(renewal_url)
        local_http = (
            parsed_url.scheme == "http"
            and (parsed_url.hostname or "").lower()
            in ("localhost", "127.0.0.1", "::1")
        )
        if parsed_url.scheme != "https" and not local_http:
            raise ValueError("Agent credential renewal requires HTTPS.")
        response = requests.post(
            renewal_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
            verify=True,
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Token renewal response must be a JSON object.")
        new_token = result.get("agent_token")
        expires_at = result.get("expires_at")
        if not isinstance(new_token, str) or not new_token:
            raise ValueError("Token renewal response did not contain an agent_token.")
        if settings.AGENT_ID and result.get("agent_id") != settings.AGENT_ID:
            raise ValueError("Token renewal response agent identity does not match enrollment.")
        if settings.TENANT_ID and result.get("tenant_id") != settings.TENANT_ID:
            raise ValueError("Token renewal response tenant identity does not match enrollment.")

        if new_token != token:
            self._persist_replacement(new_token)
        self._authentication_failed.clear()
        self._authenticated.set()

        if isinstance(expires_at, str):
            expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=timezone.utc)
            seconds_until_renewal = (
                expiration - datetime.now(timezone.utc) - RENEWAL_MARGIN
            ).total_seconds()
            return max(1.0, seconds_until_renewal)
        return 30.0

    def _renewal_loop(self) -> None:
        retry_count = 0
        delay = 0.0
        while not self._stop_event.is_set():
            self._wake_event.wait(delay)
            self._wake_event.clear()
            if self._stop_event.is_set():
                return
            try:
                delay = self._renew_once()
                retry_count = 0
            except requests.HTTPError as exc:
                response = exc.response
                if response is not None and response.status_code in (401, 403):
                    self._authenticated.clear()
                    self._authentication_failed.set()
                    logger.critical(
                        "Agent credential was rejected (%s); authenticated transmission "
                        "is disabled while renewal retries continue.",
                        response.status_code,
                    )
                retry_count += 1
                backoff = min(
                    RETRY_BASE_SECONDS * (2 ** (retry_count - 1)),
                    RETRY_MAX_SECONDS,
                )
                retry_after = (
                    retry_after_seconds(response.headers.get("Retry-After"))
                    if response is not None and response.headers
                    else None
                )
                delay = max(
                    random.uniform(backoff * 0.8, backoff * 1.2),
                    retry_after or 0.0,
                )
                logger.warning(
                    "Agent token renewal failed with HTTP %s; retrying in %.1fs.",
                    response.status_code if response is not None else "error",
                    delay,
                )
            except (
                requests.RequestException,
                ValueError,
                OSError,
                subprocess.SubprocessError,
            ) as exc:
                retry_count += 1
                backoff = min(
                    RETRY_BASE_SECONDS * (2 ** (retry_count - 1)),
                    RETRY_MAX_SECONDS,
                )
                delay = random.uniform(backoff * 0.8, backoff * 1.2)
                logger.warning(
                    "Agent token renewal failed with %s; retrying in %.1fs.",
                    type(exc).__name__,
                    delay,
                )


_token_manager = AgentTokenManager()


def start_token_renewal() -> None:
    _token_manager.start()


def stop_token_renewal() -> None:
    _token_manager.stop()


def get_current_token() -> str:
    return _token_manager.current_token


def has_authentication_failed() -> bool:
    return _token_manager.authentication_failed


def is_authenticated() -> bool:
    return _token_manager.authenticated


def report_authentication_failure() -> None:
    _token_manager.report_authentication_failure()
