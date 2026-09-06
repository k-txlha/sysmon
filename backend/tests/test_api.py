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

Compatible with both `pytest` and Python's built-in `unittest`.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure backend directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient
from main import app
from services.ch_service import ch_service


class TestBackendAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

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
        with patch.object(ch_service, "get_device_by_agent_id", return_value=mock_device):
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

        # List tokens
        list_res = self.client.get("/api/v1/agents/tokens")
        self.assertEqual(list_res.status_code, 200)
        token_strings = [t["token"] for t in list_res.json()["items"]]
        self.assertIn(token_str, token_strings)

        # Revoke token
        del_res = self.client.delete(f"/api/v1/agents/tokens/{token_str}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "success")

    # -----------------------------------------------------------------------
    # 7. Telemetry Transport & Auth
    # -----------------------------------------------------------------------
    def test_telemetry_ingestion_success(self):
        payload = {
            "agent_id": "test-agent-99",
            "device_info": {"hostname": "TEST-HOST"},
            "events": [],
        }
        with patch("services.producer.kafka_service.stream_data", return_value=None):
            response = self.client.post("/api/v1/telemetry", json=payload)
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["status"], "accepted")

    def test_telemetry_empty_payload_rejected(self):
        response = self.client.post("/api/v1/telemetry", json={})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
