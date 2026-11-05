"""Background renewal and durable persistence for the agent credential."""

from __future__ import annotations

import os
import random
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from agent.utils.config import ENV_FILE_PATH, settings
from agent.utils.logger import setup_logger

logger = setup_logger("token_manager")
RENEWAL_MARGIN = timedelta(minutes=5)
RETRY_BASE_SECONDS = 5
RETRY_MAX_SECONDS = 300


def persist_agent_configuration(
    token_file: Path,
    agent_token: str,
    backend_url: Optional[str] = None,
) -> None:
    """Atomically persist updated agent credentials in the existing env file."""
    values = {"SIEM_AGENT_TOKEN": agent_token}
    if backend_url is not None:
        values["SIEM_BACKEND_URL"] = backend_url

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
        os.replace(temporary_path, token_file)
    except OSError:
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
        self._thread: Optional[threading.Thread] = None

    @property
    def current_token(self) -> str:
        with self._lock:
            return self._token

    def start(self) -> None:
        with self._lock:
            if not self._token:
                logger.warning("Agent token is not configured; background renewal was not started.")
                return
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._renewal_loop,
                name="agent-token-renewal",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
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
        response = requests.post(
            self._renewal_url(),
            headers={"X-Agent-Token": token},
            timeout=10.0,
        )
        response.raise_for_status()
        result = response.json()
        new_token = result.get("agent_token")
        expires_at = result.get("expires_at")
        if not isinstance(new_token, str) or not new_token:
            raise ValueError("Token renewal response did not contain an agent_token.")

        if new_token != token:
            self._persist_replacement(new_token)

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
        while not self._stop_event.wait(delay):
            try:
                delay = self._renew_once()
                retry_count = 0
            except (requests.RequestException, ValueError, OSError) as exc:
                retry_count += 1
                backoff = min(
                    RETRY_BASE_SECONDS * (2 ** (retry_count - 1)),
                    RETRY_MAX_SECONDS,
                )
                delay = random.uniform(backoff * 0.8, backoff * 1.2)
                logger.warning(f"Agent token renewal failed; retrying in {delay:.1f}s: {exc}")


_token_manager = AgentTokenManager()


def start_token_renewal() -> None:
    _token_manager.start()


def stop_token_renewal() -> None:
    _token_manager.stop()


def get_current_token() -> str:
    return _token_manager.current_token
