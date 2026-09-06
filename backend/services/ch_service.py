"""
backend/services/ch_service.py

High-performance ClickHouse query service for the Sysmon REST API.
Handles structured, parameterized queries and aggregations for:
- ALERTS (threats, KPI statistics, resolution status)
- DEVICES (asset inventory, online/offline status, device history)
- EVENTS (security authentication logs, filtering, event statistics)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("clickhouse_service")


class ClickHouseQueryService:
    def __init__(self) -> None:
        self.client: Optional[Client] = None

    def connect(self) -> None:
        """Establishes client connection to ClickHouse."""
        try:
            self.client = clickhouse_connect.get_client(
                host=settings.CLICKHOUSE_HOST,
                port=settings.CLICKHOUSE_PORT,
                username=settings.CLICKHOUSE_USERNAME,
                password=settings.CLICKHOUSE_PASSWORD,
                database=settings.CLICKHOUSE_DB,
                connect_timeout=5,
                send_receive_timeout=15,
            )
            logger.info(
                f"Connected to ClickHouse database '{settings.CLICKHOUSE_DB}' at {settings.CLICKHOUSE_HOST}:{settings.CLICKHOUSE_PORT}."
            )
        except Exception as e:
            logger.error(f"Failed to connect to ClickHouse: {e}")
            self.client = None

    def disconnect(self) -> None:
        """Closes the client connection."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
            logger.info("ClickHouse connection closed.")

    def is_healthy(self) -> bool:
        """Returns True if ClickHouse is connected and responding to queries."""
        if not self.client:
            try:
                self.connect()
            except Exception:
                return False
        if not self.client:
            return False
        try:
            res = self.client.command("SELECT 1")
            return res == 1
        except Exception as e:
            logger.warning(f"ClickHouse health check ping failed: {e}")
            return False

    def _ensure_client(self) -> Client:
        if not self.client:
            self.connect()
        if not self.client:
            raise RuntimeError("ClickHouse connection is currently unavailable.")
        return self.client

    # =========================================================================
    # ALERTS
    # =========================================================================

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_name: Optional[str] = None,
        resolved: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Fetches paginated alerts with optional filters.
        Returns {'items': [...], 'total': int, 'limit': int, 'offset': int}.
        """
        client = self._ensure_client()
        conditions = ["1=1"]
        params: Dict[str, Any] = {}

        if severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = severity.upper()
        if agent_id:
            conditions.append("agent_id = %(agent_id)s")
            params["agent_id"] = agent_id
        if rule_name:
            conditions.append("rule_name = %(rule_name)s")
            params["rule_name"] = rule_name
        if resolved is not None:
            conditions.append("resolved = %(resolved)s")
            params["resolved"] = int(resolved)
        if start_time:
            conditions.append("triggered_at >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            conditions.append("triggered_at <= %(end_time)s")
            params["end_time"] = end_time

        where_clause = " AND ".join(conditions)

        # Count total
        count_query = f"SELECT count() FROM ALERTS WHERE {where_clause}"
        total_res = client.query(count_query, parameters=params)
        total = total_res.result_rows[0][0] if total_res.result_rows else 0

        # Query items
        query = f"""
            SELECT
                toString(alert_id) AS alert_id,
                rule_name,
                severity,
                agent_id,
                triggered_at,
                message,
                context,
                resolved
            FROM ALERTS
            WHERE {where_clause}
            ORDER BY triggered_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset

        result = client.query(query, parameters=params)
        items = []
        for row in result.result_rows:
            raw_ctx = row[6]
            parsed_ctx = {}
            if raw_ctx:
                try:
                    parsed_ctx = json.loads(raw_ctx)
                except Exception:
                    parsed_ctx = {"raw": raw_ctx}

            items.append(
                {
                    "alert_id": row[0],
                    "rule_name": row[1],
                    "severity": row[2],
                    "agent_id": row[3],
                    "triggered_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
                    "message": row[5],
                    "context": parsed_ctx,
                    "resolved": bool(row[7]),
                }
            )

        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetches a single alert by UUID string."""
        client = self._ensure_client()
        query = """
            SELECT
                toString(alert_id) AS alert_id,
                rule_name,
                severity,
                agent_id,
                triggered_at,
                message,
                context,
                resolved
            FROM ALERTS
            WHERE toString(alert_id) = %(alert_id)s
            LIMIT 1
        """
        result = client.query(query, parameters={"alert_id": alert_id})
        if not result.result_rows:
            return None

        row = result.result_rows[0]
        parsed_ctx = {}
        if row[6]:
            try:
                parsed_ctx = json.loads(row[6])
            except Exception:
                parsed_ctx = {"raw": row[6]}

        return {
            "alert_id": row[0],
            "rule_name": row[1],
            "severity": row[2],
            "agent_id": row[3],
            "triggered_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
            "message": row[5],
            "context": parsed_ctx,
            "resolved": bool(row[7]),
        }

    def resolve_alert(self, alert_id: str, resolved: bool = True) -> bool:
        """
        Updates the resolved state of an alert.
        Uses ALTER TABLE UPDATE in ClickHouse.
        """
        client = self._ensure_client()
        resolved_val = 1 if resolved else 0
        mutation_sql = f"""
            ALTER TABLE ALERTS
            UPDATE resolved = {resolved_val}
            WHERE toString(alert_id) = '{alert_id}'
        """
        try:
            client.command(mutation_sql)
            return True
        except Exception as e:
            logger.error(f"Failed to update alert resolution: {e}")
            raise

    def get_alert_stats(self) -> Dict[str, Any]:
        """Calculates KPI statistics across all alerts and for the last 24h."""
        client = self._ensure_client()

        # Overall summary
        summary_query = """
            SELECT
                count() AS total,
                countIf(resolved = 0) AS open,
                countIf(resolved = 1) AS resolved,
                countIf(severity = 'CRITICAL') AS critical_count,
                countIf(severity = 'HIGH') AS high_count,
                countIf(severity = 'MEDIUM') AS medium_count,
                countIf(severity = 'LOW') AS low_count,
                countIf(triggered_at >= now() - INTERVAL 24 HOUR) AS last_24h_count
            FROM ALERTS
        """
        sum_res = client.query(summary_query)
        r = sum_res.result_rows[0] if sum_res.result_rows else (0, 0, 0, 0, 0, 0, 0, 0)
        stats: Dict[str, Any] = {
            "total_alerts": r[0],
            "open_alerts": r[1],
            "resolved_alerts": r[2],
            "by_severity": {
                "CRITICAL": r[3],
                "HIGH": r[4],
                "MEDIUM": r[5],
                "LOW": r[6],
            },
            "last_24h_total": r[7],
        }

        # Top 5 rules
        top_rules_query = """
            SELECT rule_name, severity, count() AS hits
            FROM ALERTS
            GROUP BY rule_name, severity
            ORDER BY hits DESC
            LIMIT 5
        """
        top_res = client.query(top_rules_query)
        stats["top_rules"] = [
            {"rule_name": row[0], "severity": row[1], "count": row[2]}
            for row in top_res.result_rows
        ]

        # 24-hour hourly trend
        timeline_query = """
            SELECT
                toStartOfHour(triggered_at) AS hour,
                count() AS count,
                countIf(severity = 'CRITICAL') AS critical
            FROM ALERTS
            WHERE triggered_at >= now() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour ASC
        """
        timeline_res = client.query(timeline_query)
        stats["timeline_24h"] = [
            {
                "hour": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                "count": row[1],
                "critical": row[2],
            }
            for row in timeline_res.result_rows
        ]

        return stats

    # =========================================================================
    # DEVICES
    # =========================================================================

    def get_devices(self) -> List[Dict[str, Any]]:
        """
        Retrieves the latest record for every distinct agent_id.
        Adds computed online/offline status (online if updated within last 5 minutes).
        """
        client = self._ensure_client()
        query = """
            SELECT
                agent_id,
                argMax(hostname, updated_at) AS hostname,
                argMax(ip_address, updated_at) AS ip_address,
                argMax(mac_address, updated_at) AS mac_address,
                argMax(total_memory, updated_at) AS total_memory,
                argMax(operating_system, updated_at) AS operating_system,
                argMax(operating_system_name, updated_at) AS operating_system_name,
                argMax(operating_system_version, updated_at) AS operating_system_version,
                argMax(operating_system_release, updated_at) AS operating_system_release,
                argMax(machine_architecture, updated_at) AS machine_architecture,
                max(updated_at) AS last_seen
            FROM DEVICES
            GROUP BY agent_id
            ORDER BY last_seen DESC
        """
        result = client.query(query)
        devices = []
        now_utc = datetime.now(timezone.utc)
        online_threshold = timedelta(minutes=5)

        for row in result.result_rows:
            last_seen_dt = row[10]
            if last_seen_dt and hasattr(last_seen_dt, "tzinfo") and last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)

            is_online = False
            if last_seen_dt:
                is_online = (now_utc - last_seen_dt) <= online_threshold

            devices.append(
                {
                    "agent_id": row[0],
                    "hostname": row[1],
                    "ip_address": row[2],
                    "mac_address": row[3],
                    "total_memory": row[4],
                    "operating_system": row[5],
                    "operating_system_name": row[6],
                    "operating_system_version": row[7],
                    "operating_system_release": row[8],
                    "machine_architecture": row[9],
                    "last_seen": last_seen_dt.isoformat() if last_seen_dt else None,
                    "status": "online" if is_online else "offline",
                }
            )
        return devices

    def get_device_by_agent_id(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Fetches the latest profile for a single agent_id."""
        devices = self.get_devices()
        for d in devices:
            if d["agent_id"] == agent_id:
                return d
        return None

    def get_device_history(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches historical device snapshot records for an agent."""
        client = self._ensure_client()
        query = """
            SELECT
                agent_id,
                hostname,
                ip_address,
                mac_address,
                total_memory,
                operating_system,
                operating_system_name,
                operating_system_version,
                machine_architecture,
                updated_at
            FROM DEVICES
            WHERE agent_id = %(agent_id)s
            ORDER BY updated_at DESC
            LIMIT %(limit)s
        """
        result = client.query(query, parameters={"agent_id": agent_id, "limit": limit})
        history = []
        for row in result.result_rows:
            history.append(
                {
                    "agent_id": row[0],
                    "hostname": row[1],
                    "ip_address": row[2],
                    "mac_address": row[3],
                    "total_memory": row[4],
                    "operating_system": row[5],
                    "operating_system_name": row[6],
                    "operating_system_version": row[7],
                    "machine_architecture": row[8],
                    "updated_at": row[9].isoformat() if hasattr(row[9], "isoformat") else str(row[9]),
                }
            )
        return history

    def get_device_stats(self) -> Dict[str, Any]:
        """Calculates device metrics: online/offline counts and OS breakdown."""
        devices = self.get_devices()
        total = len(devices)
        online_count = sum(1 for d in devices if d["status"] == "online")
        offline_count = total - online_count

        os_counts: Dict[str, int] = {}
        for d in devices:
            os_name = d.get("operating_system_name") or d.get("operating_system") or "Unknown"
            os_counts[os_name] = os_counts.get(os_name, 0) + 1

        return {
            "total_devices": total,
            "online_devices": online_count,
            "offline_devices": offline_count,
            "os_breakdown": os_counts,
        }

    # =========================================================================
    # EVENTS
    # =========================================================================

    def get_events(
        self,
        limit: int = 50,
        offset: int = 0,
        agent_id: Optional[str] = None,
        event_id: Optional[int] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: Optional[str] = None,
        logon_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Searchable security events query with pagination.
        Returns {'items': [...], 'total': int, 'limit': int, 'offset': int}.
        """
        client = self._ensure_client()
        conditions = ["1=1"]
        params: Dict[str, Any] = {}

        if agent_id:
            conditions.append("agent_id = %(agent_id)s")
            params["agent_id"] = agent_id
        if event_id is not None:
            conditions.append("event_id = %(event_id)s")
            params["event_id"] = int(event_id)
        if username:
            conditions.append("username ILIKE %(username)s")
            params["username"] = f"%{username}%"
        if source_ip:
            conditions.append("source_ip ILIKE %(source_ip)s")
            params["source_ip"] = f"%{source_ip}%"
        if status:
            conditions.append("status = %(status)s")
            params["status"] = status.upper()
        if logon_type:
            conditions.append("logon_type = %(logon_type)s")
            params["logon_type"] = str(logon_type)
        if start_time:
            conditions.append("timestamp >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            conditions.append("timestamp <= %(end_time)s")
            params["end_time"] = end_time

        where_clause = " AND ".join(conditions)

        count_query = f"SELECT count() FROM EVENTS WHERE {where_clause}"
        total_res = client.query(count_query, parameters=params)
        total = total_res.result_rows[0][0] if total_res.result_rows else 0

        query = f"""
            SELECT
                agent_id,
                timestamp,
                event_id,
                status,
                username,
                domain,
                logon_type,
                source_ip
            FROM EVENTS
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset

        result = client.query(query, parameters=params)
        items = []
        for row in result.result_rows:
            items.append(
                {
                    "agent_id": row[0],
                    "timestamp": row[1].isoformat() if hasattr(row[1], "isoformat") else str(row[1]),
                    "event_id": row[2],
                    "status": row[3],
                    "username": row[4],
                    "domain": row[5],
                    "logon_type": row[6],
                    "source_ip": row[7],
                }
            )

        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def get_event_stats(self) -> Dict[str, Any]:
        """Calculates security authentication event KPI metrics."""
        client = self._ensure_client()

        # Overall in last 24h
        sum_query = """
            SELECT
                count() AS total_24h,
                countIf(status = 'SUCCESS') AS success_count,
                countIf(status = 'FAILURE') AS failure_count,
                countIf(event_id = 4625) AS failed_logins,
                countIf(event_id = 4624) AS successful_logins
            FROM EVENTS
            WHERE timestamp >= now() - INTERVAL 24 HOUR
        """
        sum_res = client.query(sum_query)
        r = sum_res.result_rows[0] if sum_res.result_rows else (0, 0, 0, 0, 0)
        stats: Dict[str, Any] = {
            "last_24h_total": r[0],
            "success_count": r[1],
            "failure_count": r[2],
            "failed_logins": r[3],
            "successful_logins": r[4],
        }

        # Top 5 targeted usernames (failures)
        top_users_query = """
            SELECT username, count() AS hits
            FROM EVENTS
            WHERE status = 'FAILURE' AND username != '' AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY username
            ORDER BY hits DESC
            LIMIT 5
        """
        top_u_res = client.query(top_users_query)
        stats["top_failed_usernames"] = [
            {"username": row[0], "count": row[1]} for row in top_u_res.result_rows
        ]

        # Top 5 attacker source IPs (failures)
        top_ips_query = """
            SELECT source_ip, count() AS hits
            FROM EVENTS
            WHERE status = 'FAILURE' AND source_ip != '' AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY source_ip
            ORDER BY hits DESC
            LIMIT 5
        """
        top_ip_res = client.query(top_ips_query)
        stats["top_attacker_ips"] = [
            {"source_ip": row[0], "count": row[1]} for row in top_ip_res.result_rows
        ]

        return stats


ch_service = ClickHouseQueryService()
