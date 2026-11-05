from __future__ import annotations

import sqlite3
import tempfile
import uuid
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import TestCase

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.auth_service import AUTH_SESSION_COOKIE, auth_service

PASSWORD = "Secure-Test-Password-2026!"


class TestAdministratorAuthentication(TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        auth_service.database_path = Path(self.temp_dir.name) / "sysmon_auth.db"
        self.client = TestClient(
            app,
            client=(f"127.0.0.{uuid.uuid4().int % 253 + 2}", 54101),
        )
        self.addCleanup(self.client.close)
        self.addCleanup(self.temp_dir.cleanup)

    def register_admin(self, client: TestClient | None = None):
        target = client or self.client
        response = target.post(
            "/api/v1/auth/setup",
            json={"username": "sysmon-admin", "password": PASSWORD},
        )
        return response

    def test_setup_is_local_one_time_and_hashes_credentials(self):
        self.assertTrue(self.client.get("/api/v1/auth/status").json()["setup_required"])
        response = self.register_admin()
        self.assertEqual(response.status_code, 201)
        self.assertFalse(self.client.get("/api/v1/auth/status").json()["setup_required"])
        self.assertEqual(self.register_admin().status_code, 409)

        body = response.json()
        self.assertNotIn("session_token", body)
        session_token = response.cookies.get(AUTH_SESSION_COOKIE)
        self.assertIsNotNone(session_token)
        self.assertIn("httponly", response.headers.get("set-cookie", "").lower())
        with closing(sqlite3.connect(auth_service.database_path)) as connection:
            password_hash = connection.execute(
                "SELECT password_hash FROM admin_users"
            ).fetchone()[0]
            session_hash = connection.execute(
                "SELECT session_token_hash FROM admin_sessions"
            ).fetchone()[0]
        self.assertTrue(password_hash.startswith("$argon2id$"))
        self.assertNotEqual(password_hash, PASSWORD)
        self.assertNotEqual(session_hash, session_token)

    def test_setup_rejects_non_local_client_and_weak_password(self):
        remote_client = TestClient(app, client=("192.0.2.10", 54102))
        self.addCleanup(remote_client.close)
        remote = remote_client.post(
            "/api/v1/auth/setup",
            json={"username": "sysmon-admin", "password": PASSWORD},
        )
        self.assertEqual(remote.status_code, 403)
        proxied = self.client.post(
            "/api/v1/auth/setup",
            json={"username": "sysmon-admin", "password": PASSWORD},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        self.assertEqual(proxied.status_code, 403)

        weak = self.client.post(
            "/api/v1/auth/setup",
            json={"username": "sysmon-admin", "password": "password123456"},
        )
        self.assertEqual(weak.status_code, 400)
        self.assertTrue(self.client.get("/api/v1/auth/status").json()["setup_required"])

    def test_concurrent_setup_creates_exactly_one_admin(self):
        second_client = TestClient(
            app,
            client=(f"127.0.0.{uuid.uuid4().int % 253 + 2}", 54103),
        )
        self.addCleanup(second_client.close)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    self.register_admin,
                    (self.client, second_client),
                )
            )
        self.assertEqual(sorted(response.status_code for response in results), [201, 409])
        with closing(sqlite3.connect(auth_service.database_path)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
        self.assertEqual(count, 1)

    def test_login_errors_are_generic_and_csrf_protects_logout(self):
        self.assertEqual(self.register_admin().status_code, 201)
        login = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "sysmon-admin",
                "password": "incorrect-password",
                "agent_id": f"spoofed-{uuid.uuid4().hex}",
            },
        )
        unknown = self.client.post(
            "/api/v1/auth/login",
            json={"username": "unknown-admin", "password": "incorrect-password"},
        )
        self.assertEqual(login.status_code, 401)
        self.assertEqual(login.json()["detail"], unknown.json()["detail"])

        second_client = TestClient(
            app,
            client=(f"127.0.0.{uuid.uuid4().int % 253 + 2}", 54104),
        )
        self.addCleanup(second_client.close)
        authenticated = second_client.post(
            "/api/v1/auth/login",
            json={"username": "sysmon-admin", "password": PASSWORD},
        )
        self.assertEqual(authenticated.status_code, 200)
        me = second_client.get("/api/v1/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(
            second_client.post("/api/v1/auth/logout").status_code, 403
        )
        logged_out = second_client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": me.json()["csrf_token"]},
        )
        self.assertEqual(logged_out.status_code, 200)
        self.assertEqual(second_client.get("/api/v1/auth/me").status_code, 401)

    def test_password_change_revokes_every_session(self):
        registration = self.register_admin()
        self.assertEqual(registration.status_code, 201)
        second_client = TestClient(
            app,
            client=(f"127.0.0.{uuid.uuid4().int % 253 + 2}", 54105),
        )
        self.addCleanup(second_client.close)
        other_session = second_client.post(
            "/api/v1/auth/login",
            json={"username": "sysmon-admin", "password": PASSWORD},
        )
        self.assertEqual(other_session.status_code, 200)

        changed = self.client.post(
            "/api/v1/auth/password",
            json={"new_password": "Another-Secure-Password-2026!"},
            headers={"X-CSRF-Token": registration.json()["csrf_token"]},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(second_client.get("/api/v1/auth/me").status_code, 401)
        old_login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "sysmon-admin", "password": PASSWORD},
        )
        new_login = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "sysmon-admin",
                "password": "Another-Secure-Password-2026!",
            },
        )
        self.assertEqual(old_login.status_code, 401)
        self.assertEqual(new_login.status_code, 200)

    def test_management_routes_require_admin(self):
        self.register_admin()
        unauthenticated = TestClient(app, client=("127.0.0.1", 54106))
        self.addCleanup(unauthenticated.close)
        self.assertEqual(unauthenticated.get("/api/v1/alerts").status_code, 401)
        self.assertEqual(
            unauthenticated.post("/api/v1/agents/token").status_code, 401
        )
        self.assertEqual(unauthenticated.get("/health").status_code, 200)
        self.assertEqual(
            unauthenticated.post("/api/v1/telemetry", json={}).status_code,
            401,
        )

    def test_login_is_rate_limited(self):
        limited_client = TestClient(
            app,
            client=(f"127.0.0.{uuid.uuid4().int % 253 + 2}", 54107),
        )
        self.addCleanup(limited_client.close)
        self.assertEqual(self.register_admin(limited_client).status_code, 201)
        responses = [
            limited_client.post(
                "/api/v1/auth/login",
                json={"username": "sysmon-admin", "password": "incorrect-password"},
            )
            for _ in range(6)
        ]
        self.assertTrue(all(response.status_code == 401 for response in responses[:5]))
        self.assertEqual(responses[5].status_code, 429)
