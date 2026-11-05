"""
backend/tests/test_api.py

Unit and integration tests for Sysmon Backend REST API endpoints (Phase 2):
- /health & /
- /api/v1/alerts (listing, stats, detail, resolution)
- /api/v1/devices (listing, stats, single device, history)
- /api/v1/events (listing, stats, filters)
- /api/v1/rules (listing, detail, toggling)
- /api/v1/agents (listing, token generation, token revocation)
- /api/v1/telemetry (ingestion, auth checking)
"""

from __future__ import annotations

import tempfile
import sqlite3
from contextlib import closing
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import main as backend_main
from backend.services.agent_service import AgentService, agent_service
from backend.services.auth_service import auth_service
from backend.services.ch_service import ch_service

app = backend_main.app


class TestBackendAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        auth_service.database_path = Path(self.temp_dir.name) / "sysmon_auth.db"
        self.client = TestClient(app, client=("127.0.0.1", 54321))
        setup = self.client.post(
            "/api/v1/auth/setup",
            json={
                "username": "sysmon-admin",
                "password": "Secure-Test-Password-2026!",
            },
        )
        self.assertEqual(setup.status_code, 201, setup.text)
        self.client.headers.update({"X-CSRF-Token": setup.json()["csrf_token"]})
        self.addCleanup(self.client.close)
        self.addCleanup(self.temp_dir.cleanup)

    def create_agent_credential(self, hostname: str | None = None) -> str:
        hostname = hostname or f"test-agent-{uuid.uuid4().hex[:12]}"
        bootstrap = self.client.post(
            "/api/v1/agents/token", json={"description": "Telemetry test"}
        ).json()["token"]
        enrollment = self.client.post(
            "/api/v1/agents/enroll",
            json={
                "bootstrap_token": bootstrap,
                "hostname": hostname,
                "operating_system": "Linux",
                "mac_address": "00:11:22:33:44:55",
            },
        )
        self.assertEqual(enrollment.status_code, 200, enrollment.text)
        return enrollment.json()["agent_token"]

    def set_token_expiration(self, token: str, expiration: datetime) -> None:
        with closing(sqlite3.connect(auth_service.database_path)) as connection:
            connection.execute(
                "UPDATE agent_credentials SET expires_at = ? WHERE token_hash = ?",
                (expiration.isoformat(), AgentService._token_key(token)),
            )
            connection.commit()

    # -----------------------------------------------------------------------
    # 1. Health & Root Endpoints
    # -----------------------------------------------------------------------
    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "Sysmon Security Platform API")
        self.assertEqual(data["status"], "online")

    def test_health_endpoint(self):
        with patch.object(ch_service, "is_healthy", return_value=True):
            response = self.client.get("/health")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("status", data)
            self.assertIn("services", data)
            self.assertIn("uptime_seconds", data)

    # -----------------------------------------------------------------------
    # 2. Alerts API Endpoints
    # -----------------------------------------------------------------------
    def test_list_alerts(self):
        mock_alerts = {
            "items": [
                {
                    "alert_id": "11111111-2222-3333-4444-555555555555",
                    "rule_name": "brute_force",
                    "severity": "CRITICAL",
                    "agent_id": "test-agent-01",
                    "triggered_at": "2026-09-06T12:00:00Z",
                    "message": "Multiple failed logins",
                    "context": {"source_ip": "192.168.1.100"},
                    "resolved": False,
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0,
        }
        with patch.object(ch_service, "get_alerts", return_value=mock_alerts):
            response = self.client.get("/api/v1/alerts?severity=CRITICAL")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total"], 1)
            self.assertEqual(len(data["items"]), 1)
            self.assertEqual(data["items"][0]["rule_name"], "brute_force")

    def test_alert_stats(self):
        mock_stats = {
            "total_alerts": 10,
            "open_alerts": 7,
            "resolved_alerts": 3,
            "by_severity": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 1},
            "last_24h_total": 5,
            "top_rules": [{"rule_name": "brute_force", "severity": "CRITICAL", "count": 4}],
            "timeline_24h": [{"hour": "2026-09-06T10:00:00", "count": 2, "critical": 1}],
        }
        with patch.object(ch_service, "get_alert_stats", return_value=mock_stats):
            response = self.client.get("/api/v1/alerts/stats")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total_alerts"], 10)
            self.assertEqual(data["open_alerts"], 7)
            self.assertEqual(data["by_severity"]["CRITICAL"], 2)

    def test_alert_detail_found(self):
        mock_alert = {
            "alert_id": "11111111-2222-3333-4444-555555555555",
            "rule_name": "brute_force",
            "severity": "CRITICAL",
            "agent_id": "test-agent-01",
            "triggered_at": "2026-09-06T12:00:00Z",
            "message": "Multiple failed logins",
            "context": {"source_ip": "192.168.1.100"},
            "resolved": False,
        }
        with patch.object(ch_service, "get_alert_by_id", return_value=mock_alert):
            response = self.client.get("/api/v1/alerts/11111111-2222-3333-4444-555555555555")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["alert_id"], "11111111-2222-3333-4444-555555555555")

    def test_alert_detail_not_found(self):
        with patch.object(ch_service, "get_alert_by_id", return_value=None):
            response = self.client.get("/api/v1/alerts/non-existent-uuid")
            self.assertEqual(response.status_code, 404)

    def test_resolve_alert(self):
        with patch.object(ch_service, "resolve_alert", return_value=True):
            response = self.client.patch(
                "/api/v1/alerts/11111111-2222-3333-4444-555555555555/resolve",
                json={"resolved": True},
            )
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["status"], "success")
            self.assertTrue(data["resolved"])

    # -----------------------------------------------------------------------
    # 3. Devices API Endpoints
    # -----------------------------------------------------------------------
    def test_list_devices(self):
        mock_devices = [
            {
                "agent_id": "agent-pc-01",
                "hostname": "WORKSTATION-X",
                "ip_address": "192.168.1.50",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "total_memory": "16.0 GB",
                "operating_system": "Windows",
                "operating_system_name": "Windows 11 Pro",
                "operating_system_version": "10.0.22631",
                "operating_system_release": "11",
                "machine_architecture": "AMD64",
                "last_seen": "2026-09-06T12:00:00Z",
                "status": "online",
            }
        ]
        with patch.object(ch_service, "get_devices", return_value=mock_devices):
            response = self.client.get("/api/v1/devices")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["items"][0]["hostname"], "WORKSTATION-X")

    def test_device_stats(self):
        mock_stats = {
            "total_devices": 5,
            "online_devices": 4,
            "offline_devices": 1,
            "os_breakdown": {"Windows 11 Pro": 3, "Ubuntu 22.04": 2},
        }
        with patch.object(ch_service, "get_device_stats", return_value=mock_stats):
            response = self.client.get("/api/v1/devices/stats")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total_devices"], 5)
            self.assertEqual(data["online_devices"], 4)

    def test_device_detail(self):
        mock_device = {
            "agent_id": "agent-pc-01",
            "hostname": "WORKSTATION-X",
            "ip_address": "192.168.1.50",
            "mac_address": "00:1A:2B:3C:4D:5E",
            "total_memory": "16.0 GB",
            "operating_system": "Windows",
            "operating_system_name": "Windows 11 Pro",
            "operating_system_version": "10.0.22631",
            "operating_system_release": "11",
            "machine_architecture": "AMD64",
            "last_seen": "2026-09-06T12:00:00Z",
            "status": "online",
        }
        with patch.object(ch_service, "get_device_by_agent_id", return_value=mock_device), \
             patch.object(ch_service, "get_agent_health", return_value=None):
            response = self.client.get("/api/v1/devices/agent-pc-01")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["agent_id"], "agent-pc-01")

    def test_device_history(self):
        mock_history = [
            {
                "agent_id": "agent-pc-01",
                "hostname": "WORKSTATION-X",
                "ip_address": "192.168.1.50",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "total_memory": "16.0 GB",
                "operating_system": "Windows",
                "operating_system_name": "Windows 11 Pro",
                "operating_system_version": "10.0.22631",
                "machine_architecture": "AMD64",
                "updated_at": "2026-09-06T12:00:00Z",
            }
        ]
        with patch.object(ch_service, "get_device_history", return_value=mock_history):
            response = self.client.get("/api/v1/devices/agent-pc-01/history")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["history"][0]["hostname"], "WORKSTATION-X")

    # -----------------------------------------------------------------------
    # 4. Events API Endpoints
    # -----------------------------------------------------------------------
    def test_list_events(self):
        mock_events = {
            "items": [
                {
                    "agent_id": "agent-pc-01",
                    "timestamp": "2026-09-06T12:00:00Z",
                    "event_id": 4625,
                    "status": "FAILURE",
                    "username": "administrator",
                    "domain": "CORP",
                    "logon_type": "3",
                    "source_ip": "10.0.0.5",
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0,
        }
        with patch.object(ch_service, "get_events", return_value=mock_events):
            response = self.client.get("/api/v1/events?status=FAILURE&username=admin")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["items"][0]["status"], "FAILURE")

    def test_event_stats(self):
        mock_stats = {
            "last_24h_total": 1500,
            "success_count": 1400,
            "failure_count": 100,
            "failed_logins": 100,
            "successful_logins": 1400,
            "top_failed_usernames": [{"username": "root", "count": 60}],
            "top_attacker_ips": [{"source_ip": "192.168.1.99", "count": 75}],
        }
        with patch.object(ch_service, "get_event_stats", return_value=mock_stats):
            response = self.client.get("/api/v1/events/stats")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["last_24h_total"], 1500)
            self.assertEqual(data["failure_count"], 100)

    # -----------------------------------------------------------------------
    # 5. Rules API Endpoints
    # -----------------------------------------------------------------------
    def test_list_rules(self):
        response = self.client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("items", data)
        self.assertGreater(data["total"], 0)

    def test_toggle_rule(self):
        list_res = self.client.get("/api/v1/rules")
        if list_res.json()["total"] > 0:
            target_rule = list_res.json()["items"][0]["name"]
            orig_enabled = list_res.json()["items"][0]["enabled"]

            toggle_res = self.client.post(
                f"/api/v1/rules/{target_rule}/toggle",
                json={"enabled": not orig_enabled},
            )
            self.assertEqual(toggle_res.status_code, 200)
            self.assertEqual(toggle_res.json()["enabled"], not orig_enabled)

            # Restore original state
            self.client.post(
                f"/api/v1/rules/{target_rule}/toggle",
                json={"enabled": orig_enabled},
            )

    # -----------------------------------------------------------------------
    # 6. Agents & Token Management API
    # -----------------------------------------------------------------------
    def test_agent_token_lifecycle(self):
        # Create token
        create_res = self.client.post(
            "/api/v1/agents/token",
            json={"description": "Test Agent Token"},
        )
        self.assertEqual(create_res.status_code, 201)
        token_data = create_res.json()
        self.assertIn("token", token_data)
        token_str = token_data["token"]
        self.assertTrue(token_str.startswith("sysmon_tok_"))
        token_key = AgentService._token_key(token_str)
        with closing(sqlite3.connect(auth_service.database_path)) as connection:
            stored_hash = connection.execute(
                "SELECT token_hash FROM agent_credentials WHERE id = ?",
                (token_data["token_id"],),
            ).fetchone()[0]
        self.assertEqual(stored_hash, token_key)
        self.assertNotEqual(stored_hash, token_str)

        # List tokens
        list_res = self.client.get("/api/v1/agents/tokens")
        self.assertEqual(list_res.status_code, 200)
        token_entries = list_res.json()["items"]
        self.assertTrue(token_entries)
        self.assertNotIn("token", token_entries[0])
        self.assertNotIn("token_hash", token_entries[0])
        self.assertNotIn("agent_token", token_entries[0])
        token_ids = [t["id"] for t in token_entries]
        self.assertIn(token_data["token_id"], token_ids)

        # Revoke token
        del_res = self.client.delete(f"/api/v1/agents/tokens/{token_data['token_id']}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "success")

    def test_agent_enroll_handshake_success(self):
        hostname = f"test-workstation-{uuid.uuid4().hex[:8]}"
        # 1. Provision a bootstrap token
        tok_res = self.client.post("/api/v1/agents/token", json={"description": "Bootstrap"})
        bootstrap_tok = tok_res.json()["token"]

        # 2. Perform agent enrollment
        enroll_res = self.client.post(
            "/api/v1/agents/enroll",
            json={
                "bootstrap_token": bootstrap_tok,
                "hostname": hostname,
                "operating_system": "Windows 11 Pro",
                "mac_address": "00:11:22:33:44:55",
                "machine_architecture": "AMD64",
                "tenant_id": "tenant_spoofed_by_agent",
            },
        )
        self.assertEqual(enroll_res.status_code, 200)
        data = enroll_res.json()
        self.assertEqual(data["status"], "enrolled")
        self.assertNotEqual(data["agent_id"], hostname)
        self.assertTrue(data["agent_id"].startswith("agent_"))
        self.assertEqual(data["tenant_id"], "default")
        self.assertTrue(data["agent_token"].startswith("sysmon_agent_"))
        reused = self.client.post(
            "/api/v1/agents/enroll",
            json={
                "bootstrap_token": bootstrap_tok,
                "hostname": hostname,
                "operating_system": "Windows 11 Pro",
                "mac_address": "00:11:22:33:44:55",
            },
        )
        self.assertEqual(reused.status_code, 401)

    def test_agent_enroll_handshake_invalid_token(self):
        enroll_res = self.client.post(
            "/api/v1/agents/enroll",
            json={
                "bootstrap_token": "sysmon_invalid_token_999",
                "hostname": "fake-host",
                "operating_system": "Linux",
                "mac_address": "00:00:00:00:00:00",
            },
        )
        self.assertEqual(enroll_res.status_code, 401)

    def test_agent_enrollment_rejects_remote_plain_http(self):
        remote_client = TestClient(app, client=("192.0.2.10", 54322))
        try:
            response = remote_client.post(
                "/api/v1/agents/enroll",
                json={
                    "bootstrap_token": "not-a-valid-token",
                    "hostname": "remote-test-host",
                    "operating_system": "Linux",
                    "mac_address": "00:00:00:00:00:00",
                },
            )
        finally:
            remote_client.close()
        self.assertEqual(response.status_code, 426)

    def test_agent_renewal_and_telemetry_reject_remote_plain_http(self):
        agent_token = self.create_agent_credential()
        remote_client = TestClient(app, client=("192.0.2.11", 54323))
        try:
            renewal = remote_client.post(
                "/api/v1/agents/renew",
                headers={"Authorization": "Bearer " + agent_token},
            )
            telemetry = remote_client.post(
                "/api/v1/telemetry",
                json={
                    "host_id": "TEST-HOST",
                    "agent_id": "any-agent",
                    "tenant_id": "default",
                    "event_type": "telemetry.snapshot",
                    "observed_at": "2026-09-16T14:30:00.000Z",
                    "source": "windows_agent",
                    "data": {},
                },
                headers={"Authorization": "Bearer " + agent_token},
            )
        finally:
            remote_client.close()
        self.assertEqual(renewal.status_code, 426)
        self.assertEqual(telemetry.status_code, 426)

    def test_agent_token_renewal_endpoint(self):
        hostname = f"renewal-endpoint-{uuid.uuid4().hex[:8]}"
        bootstrap = self.client.post(
            "/api/v1/agents/token", json={"description": "Renewal endpoint test"}
        ).json()["token"]
        enrollment = self.client.post(
            "/api/v1/agents/enroll",
            json={
                "bootstrap_token": bootstrap,
                "hostname": hostname,
                "operating_system": "Linux",
                "mac_address": "00:11:22:33:44:77",
            },
        )
        self.assertEqual(enrollment.status_code, 200)
        old_token = enrollment.json()["agent_token"]

        not_due = self.client.post(
            "/api/v1/agents/renew",
            headers={"X-Agent-Token": old_token},
        )
        self.assertEqual(not_due.status_code, 200)
        self.assertFalse(not_due.json()["renewed"])
        self.assertEqual(not_due.json()["agent_token"], old_token)

        self.set_token_expiration(
            old_token, datetime.now(timezone.utc) + timedelta(minutes=1)
        )
        renewed = self.client.post(
            "/api/v1/agents/renew",
            headers={"X-Agent-Token": old_token},
        )
        self.assertEqual(renewed.status_code, 200)
        self.assertTrue(renewed.json()["renewed"])
        self.assertEqual(
            renewed.json()["agent_id"],
            agent_service._load_token(old_token)["agent_id"],
        )
        self.assertNotEqual(renewed.json()["agent_token"], old_token)

        replacement = renewed.json()["agent_token"]
        credential_ids = {
            entry["agent_id"]: entry["id"]
            for entry in self.client.get("/api/v1/agents/tokens").json()["items"]
            if entry["agent_id"] == enrollment.json()["agent_id"]
            and entry["token_type"] == "agent"
        }
        revoked = self.client.delete(
            f"/api/v1/agents/tokens/{credential_ids[enrollment.json()['agent_id']]}"
        )
        self.assertEqual(revoked.status_code, 200)
        rejected = self.client.post(
            "/api/v1/agents/renew",
            headers={"X-Agent-Token": replacement},
        )
        self.assertEqual(rejected.status_code, 403)
        telemetry_rejected = self.client.post(
            "/api/v1/telemetry",
            json={
                "host_id": "TEST-HOST",
                "agent_id": enrollment.json()["agent_id"],
                "tenant_id": "default",
                "event_type": "telemetry.snapshot",
                "observed_at": "2026-09-16T14:30:00.000Z",
                "source": "windows_agent",
                "data": {},
            },
            headers={"Authorization": "Bearer " + replacement},
        )
        self.assertEqual(telemetry_rejected.status_code, 401)

    def test_expired_agent_credential_is_rejected(self):
        agent_token = self.create_agent_credential()
        identity = agent_service._load_token(agent_token)
        self.set_token_expiration(
            agent_token, datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        response = self.client.post(
            "/api/v1/telemetry",
            json={
                "host_id": "TEST-HOST",
                "agent_id": identity["agent_id"],
                "tenant_id": identity["tenant_id"],
                "event_type": "telemetry.snapshot",
                "observed_at": "2026-09-16T14:30:00.000Z",
                "source": "windows_agent",
                "data": {},
            },
            headers={"Authorization": "Bearer " + agent_token},
        )
        self.assertEqual(response.status_code, 401)

    def test_device_health_endpoint(self):
        mock_health = {
            "agent_id": "test-agent-01",
            "timestamp": "2026-10-02T12:00:00Z",
            "cpu_percent": 1.5,
            "memory_rss_mb": 42.0,
            "queue_depth": 0,
            "dropped_events_total": 0,
            "buffer_bytes": 1024,
            "uptime_seconds": 3600.0,
        }
        with patch.object(ch_service, "get_agent_health", return_value=mock_health):
            res = self.client.get("/api/v1/devices/test-agent-01/health")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "active")
            self.assertEqual(data["health"]["cpu_percent"], 1.5)

    # -----------------------------------------------------------------------
    # 7. Telemetry Transport & Auth
    # -----------------------------------------------------------------------
    def test_telemetry_envelope_ingestion_success(self):
        agent_id = f"identity-bound-agent-{uuid.uuid4().hex[:8]}"
        agent_token = self.create_agent_credential(agent_id)
        payload = {
            "event_id": "11111111-2222-3333-4444-555555555555",
            "schema_version": 1,
            "tenant_id": "default",
            "host_id": "TEST-HOST",
            "agent_id": agent_service._load_token(agent_token)["agent_id"],
            "event_type": "telemetry.snapshot",
            "observed_at": "2026-09-16T14:30:00.000Z",
            "sequence": 1,
            "source": "windows_agent",
            "severity": "informational",
            "data": {"cpu": 15.0},
        }
        with patch("backend.services.producer.kafka_service.stream_batch", return_value=None) as stream:
            response = self.client.post(
                "/api/v1/telemetry",
                json=payload,
                headers={"Authorization": "Bearer " + agent_token},
            )
            self.assertEqual(response.status_code, 202)
            data = response.json()
            self.assertEqual(data["status"], "accepted")
            self.assertEqual(data["ingested_count"], 1)
            self.assertIn("received_at", data)
            self.assertEqual(
                stream.call_args.args[1][0]["agent_id"],
                agent_service._load_token(agent_token)["agent_id"],
            )

    def test_telemetry_batch_envelope_ingestion_success(self):
        agent_id = f"batch-identity-agent-{uuid.uuid4().hex[:8]}"
        agent_token = self.create_agent_credential(agent_id)
        payload = {
            "events": [
                {
                    "event_id": "11111111-2222-3333-4444-555555555551",
                    "schema_version": 1,
                    "host_id": "TEST-HOST",
                    "agent_id": agent_service._load_token(agent_token)["agent_id"],
                    "event_type": "telemetry.snapshot",
                    "observed_at": "2026-09-16T14:30:00.000Z",
                    "sequence": 1,
                    "source": "windows_agent",
                    "severity": "informational",
                    "data": {},
                },
                {
                    "event_id": "11111111-2222-3333-4444-555555555552",
                    "schema_version": 1,
                    "host_id": "TEST-HOST",
                    "agent_id": agent_service._load_token(agent_token)["agent_id"],
                    "event_type": "security.auth",
                    "observed_at": "2026-09-16T14:30:01.000Z",
                    "sequence": 2,
                    "source": "windows_agent",
                    "severity": "medium",
                    "data": {"status": "FAILURE"},
                },
            ]
        }
        with patch("backend.services.producer.kafka_service.stream_batch", return_value=None) as stream:
            response = self.client.post(
                "/api/v1/telemetry",
                json=payload,
                headers={"X-Agent-Token": agent_token},
            )
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["ingested_count"], 2)
            self.assertEqual(
                {event["agent_id"] for event in stream.call_args.args[1]},
                {agent_service._load_token(agent_token)["agent_id"]},
            )

    def test_telemetry_rejects_conflicting_agent_and_tenant_identity(self):
        agent_token = self.create_agent_credential()
        identity = agent_service._load_token(agent_token)
        payload = {
            "host_id": "TEST-HOST",
            "agent_id": identity["agent_id"],
            "tenant_id": identity["tenant_id"],
            "event_type": "telemetry.snapshot",
            "observed_at": "2026-09-16T14:30:00.000Z",
            "source": "windows_agent",
            "data": {},
        }
        conflicting_agent = {**payload, "agent_id": "agent_spoofed"}
        response = self.client.post(
            "/api/v1/telemetry",
            json=conflicting_agent,
            headers={"Authorization": "Bearer " + agent_token},
        )
        self.assertEqual(response.status_code, 403)

        conflicting_tenant = {**payload, "tenant_id": "tenant_spoofed"}
        response = self.client.post(
            "/api/v1/telemetry",
            json=conflicting_tenant,
            headers={"Authorization": "Bearer " + agent_token},
        )
        self.assertEqual(response.status_code, 403)

    def test_telemetry_invalid_schema_rejected(self):
        # Invalid schema missing required envelope fields
        invalid_payload = {"legacy_data": "unknown_format"}
        response = self.client.post(
            "/api/v1/telemetry",
            json=invalid_payload,
            headers={"X-Agent-Token": self.create_agent_credential()},
        )
        self.assertEqual(response.status_code, 422)

    def test_telemetry_empty_payload_rejected(self):
        response = self.client.post(
            "/api/v1/telemetry",
            json={},
            headers={"X-Agent-Token": self.create_agent_credential()},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
