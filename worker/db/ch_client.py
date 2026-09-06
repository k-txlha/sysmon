import json
import clickhouse_connect
from utils.config import settings
from utils.logger import setup_logger

logger = setup_logger("clickhouse_service")


class ClickHouseService:
    def __init__(self):
        self.client = None

    def connect(self):
        self.client = clickhouse_connect.get_client(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            username=settings.CLICKHOUSE_USERNAME,
            password=settings.CLICKHOUSE_PASSWORD,
            database=settings.CLICKHOUSE_DB,
        )
        logger.info(f"Connected to ClickHouse successfully.")
        self.init_db()

    def init_db(self):
        self.client.command("""
                            CREATE TABLE IF NOT EXISTS DEVICES (
                                agent_id String,
                                hostname String,
                                ip_address String,
                                mac_address String,
                                total_memory String,
                                operating_system String,
                                operating_system_name String,
                                operating_system_version String,
                                operating_system_release String,
                                machine_architecture String,
                                is_latest UInt8,
                                updated_at DateTime64(3, 'UTC')
                                ) ENGINE = MergeTree()
                            ORDER BY (agent_id, updated_at);
                            """)

        self.client.command("""
                            CREATE TABLE IF NOT EXISTS EVENTS (
                                agent_id String,
                                timestamp DateTime64(3, 'UTC'),
                                event_id UInt32,
                                status String,
                                username String,
                                domain String,
                                logon_type String,
                                source_ip String
                                ) ENGINE = MergeTree()
                            ORDER BY (agent_id, timestamp, event_id);
                            """)

        # ALERTS — fired detection rule hits, persisted for dashboard queries
        self.client.command("""
                            CREATE TABLE IF NOT EXISTS ALERTS (
                                alert_id     UUID DEFAULT generateUUIDv4(),
                                rule_name    String,
                                severity     String,
                                agent_id     String,
                                triggered_at DateTime64(3, 'UTC'),
                                message      String,
                                context      String,
                                resolved     UInt8 DEFAULT 0
                                ) ENGINE = MergeTree()
                            ORDER BY (triggered_at, severity, agent_id);
                            """)
        logger.info("ClickHouse schemas initialized successfully.")

    def insert_devices_batch(self, rows: list):
        """Performs a bulk insert of device asset tracking records."""
        if not rows:
            return
        try:
            self.client.insert(
                f"{settings.CLICKHOUSE_DB}.DEVICES",
                rows,
                column_names=[
                    "agent_id",
                    "hostname",
                    "ip_address",
                    "mac_address",
                    "total_memory",
                    "operating_system",
                    "operating_system_name",
                    "operating_system_version",
                    "operating_system_release",
                    "machine_architecture",
                    "is_latest",
                    "updated_at",
                ],
            )
            logger.info(f"Successfully flushed {len(rows)} rows to DEVICES table.")
        except Exception as e:
            logger.error(f"Failed to batch insert into DEVICES: {e}")

    def insert_events_batch(self, rows: list):
        """Performs a bulk insert of security authentication logs."""
        if not rows:
            return
        try:
            self.client.insert(
                f"{settings.CLICKHOUSE_DB}.EVENTS",
                rows,
                column_names=[
                    "agent_id",
                    "timestamp",
                    "event_id",
                    "status",
                    "username",
                    "domain",
                    "logon_type",
                    "source_ip",
                ],
            )
            logger.info(f"Successfully flushed {len(rows)} rows to EVENTS table.")
        except Exception as e:
            logger.error(f"Failed to batch insert into EVENTS: {e}")

    def insert_alerts_batch(self, alerts: list) -> None:
        """Persists a batch of FiredAlert objects to the ALERTS table."""
        if not alerts:
            return
        rows = [
            (
                alert.rule_name,
                alert.severity.value,
                alert.agent_id,
                alert.triggered_at,
                alert.message,
                json.dumps(alert.context, default=str),
                int(alert.resolved),
            )
            for alert in alerts
        ]
        try:
            self.client.insert(
                f"{settings.CLICKHOUSE_DB}.ALERTS",
                rows,
                column_names=[
                    "rule_name",
                    "severity",
                    "agent_id",
                    "triggered_at",
                    "message",
                    "context",
                    "resolved",
                ],
            )
            logger.info(f"Persisted {len(rows)} alert(s) to ALERTS table.")
        except Exception as e:
            logger.error(f"Failed to batch insert into ALERTS: {e}")
