import asyncio
import json
import datetime
from collections import defaultdict
from aiokafka import AIOKafkaConsumer
from db.ch_client import ClickHouseService
from utils.config import settings
from utils.logger import setup_logger

# ── Detection Engine & Alerting ─────────────────────────────────────────────
from detection import DetectionEngine
from alerting import AlertDispatcher

logger = setup_logger("worker_main")

# Performance / Batching configurations
MAX_BATCH_SIZE = int(settings.MAX_BATCH_SIZE)
MAX_WAIT_TIME = float(settings.MAX_WAIT_TIME)  # Seconds


def _parse_timestamp(ts_val: str | None) -> datetime.datetime:
    """Parses ISO-8601 / RFC3339 timestamps safely into UTC datetime."""
    if not ts_val:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    try:
        clean_ts = str(ts_val).replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_ts)
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


async def start_worker():
    # 1. Initialize and connect to ClickHouse
    db_service = ClickHouseService()
    db_service.connect()

    # 2. Initialize the Detection Engine (loads all YAML rules on startup)
    engine = DetectionEngine()

    # 3. Initialize the Alert Dispatcher (reads webhook/SMTP config from .env)
    dispatcher = AlertDispatcher()

    # 4. Initialize the Kafka Consumer
    consumer = AIOKafkaConsumer(
        settings.KAFKA_TOPIC,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        group_id="siem_workers",
        auto_offset_reset="earliest",
        max_poll_interval_ms=600000,
    )
    await consumer.start()
    logger.info(f"Kafka Worker actively consuming from topic: {settings.KAFKA_TOPIC}")

    # Initialize separate batch buffers
    device_buffer = {}  # agent_id -> device_row (deduplicates within batch window)
    event_buffer = []   # list of sequential auth log tuples

    last_flush_time = asyncio.get_event_loop().time()

    try:
        while True:
            try:
                # Poll Kafka with a 1-second timeout
                msg = await asyncio.wait_for(consumer.getone(), timeout=1.0)
                payload = json.loads(msg.value.decode("utf-8"))

                agent_id = payload.get("agent_id", "unknown_agent")
                event_type = payload.get("event_type", "telemetry.snapshot")
                observed_at_str = payload.get("observed_at") or payload.get("timestamp")
                event_timestamp = _parse_timestamp(observed_at_str)
                data = payload.get("data", {})

                # --- 1. TELEMETRY SNAPSHOT (DEVICE INVENTORY & ASSETS) ---
                if event_type == "telemetry.snapshot":
                    network = data.get("network", {})
                    platform_info = data.get("platform", {})
                    system = data.get("system", {})

                    device_row = (
                        agent_id,
                        str(network.get("hostname", "")),
                        str(network.get("ip-address", "")),
                        str(network.get("mac-address", "")),
                        str(system.get("memory_info", {}).get("total_memory", "Unknown")),
                        str(platform_info.get("operating_system", "")),
                        str(platform_info.get("operating_system_name", "")),
                        str(platform_info.get("operating_system_version", "")),
                        str(platform_info.get("operating_system_release", "")),
                        str(platform_info.get("machine_architecture", "")),
                        1,  # Staging 'is_latest' as True initially
                        event_timestamp,
                    )
                    device_buffer[agent_id] = device_row

                # --- 2. SECURITY AUTHENTICATION EVENTS ---
                elif event_type == "security.auth":
                    auth_ts_str = data.get("timestamp")
                    auth_timestamp = _parse_timestamp(auth_ts_str) if auth_ts_str else event_timestamp

                    event_row = (
                        agent_id,
                        auth_timestamp,
                        int(data.get("event_id", 0)),
                        str(data.get("status", "UNKNOWN")),
                        str(data.get("username", "unknown")),
                        str(data.get("domain", "Unknown")),
                        str(data.get("logon_type", "Unknown")),
                        str(data.get("source_ip", "Unknown")),
                    )
                    event_buffer.append(event_row)

                # --- 3. AGENT HEALTH EVENTS ---
                elif event_type == "agent.health":
                    logger.debug(
                        f"Agent health report [{agent_id}]: CPU {data.get('cpu_percent')}% | "
                        f"Memory {data.get('memory_rss_mb')}MB | Queue Depth {data.get('queue_depth')} | "
                        f"Dropped {data.get('dropped_events_total')}"
                    )

            except asyncio.TimeoutError:
                pass

            # Evaluate tracking intervals
            current_time = asyncio.get_event_loop().time()
            time_since_flush = current_time - last_flush_time

            # --- DUAL-TRIGGER FLUSH CONDITION CHECK ---
            if (
                len(event_buffer) >= MAX_BATCH_SIZE
                or len(device_buffer) >= MAX_BATCH_SIZE
            ) or (
                time_since_flush >= MAX_WAIT_TIME and (event_buffer or device_buffer)
            ):

                # 1. Flush Device Asset Updates
                if device_buffer:
                    rows_to_insert = list(device_buffer.values())
                    agent_ids_to_update = list(device_buffer.keys())

                    try:
                        formatted_ids = ", ".join(
                            [f"'{aid}'" for aid in agent_ids_to_update]
                        )
                        logger.info(
                            f"Rotating history in bulk for {len(agent_ids_to_update)} agents..."
                        )
                        db_service.client.command(f"""
                            ALTER TABLE DEVICES 
                            UPDATE is_latest = 0 
                            WHERE agent_id IN ({formatted_ids}) AND is_latest = 1
                        """)
                    except Exception as mutation_err:
                        logger.warning(
                            f"Bulk history rotation failed for batch window: {mutation_err}"
                        )

                    logger.info(
                        f"Executing batch update for {len(rows_to_insert)} hosts in DEVICES..."
                    )
                    db_service.insert_devices_batch(rows_to_insert)
                    device_buffer.clear()

                # 2. Flush Login Log Streams
                if event_buffer:
                    logger.info(
                        f"Executing batch insert for {len(event_buffer)} security audits in EVENTS..."
                    )
                    db_service.insert_events_batch(event_buffer)

                    # ── 3. Run Detection Engine on this event batch ────────────
                    events_by_agent: dict = defaultdict(list)
                    for row in event_buffer:
                        events_by_agent[row[0]].append(row)

                    all_alerts = []
                    for aid, agent_events in events_by_agent.items():
                        fired = engine.evaluate(agent_events, aid)
                        all_alerts.extend(fired)

                    # 4. Persist alerts to ClickHouse + fan-out to configured channels
                    if all_alerts:
                        logger.info(
                            f"Detection engine fired {len(all_alerts)} alert(s) "
                            f"across {len(events_by_agent)} agent(s)."
                        )
                        db_service.insert_alerts_batch(all_alerts)
                        dispatcher.dispatch(all_alerts)

                    event_buffer.clear()

                # Reset execution timer
                last_flush_time = current_time

    except KeyboardInterrupt:
        logger.info(
            "Termination signal caught. Safely disconnecting Worker components..."
        )
    finally:
        await consumer.stop()
        logger.info("Kafka Consumer connections severed cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(start_worker())
    except Exception as startup_err:
        logger.critical(f"Fatal worker runtime error occurred: {startup_err}")
