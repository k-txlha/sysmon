import asyncio
import json
import datetime
from aiokafka import AIOKafkaConsumer
from db.ch_client import ClickHouseService
from utils.config import settings
from utils.logger import setup_logger

logger = setup_logger("worker_main")

# Performance / Batching configurations
MAX_BATCH_SIZE = settings.MAX_BATCH_SIZE
MAX_WAIT_TIME = settings.MAX_WAIT_TIME  # Seconds


async def start_worker():
    # 1. Initialize and connect to ClickHouse
    db_service = ClickHouseService()
    db_service.connect()

    # 2. Initialize the Kafka Consumer
    consumer = AIOKafkaConsumer(
        settings.KAFKA_TOPIC,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        group_id="siem_workers",
        auto_offset_reset="earliest",
    )
    await consumer.start()
    logger.info(f"Kafka Worker actively consuming from topic: {settings.KAFKA_TOPIC}")

    # Initialize separate batch buffers
    device_buffer = (
        {}
    )  # Dictionary to automatically deduplicate agents within the same batch window
    event_buffer = []  # List to capture all sequential authentication logs

    last_flush_time = asyncio.get_event_loop().time()

    try:
        while True:
            try:
                # Poll Kafka with a 1-second timeout so the loop doesn't block indefinitely
                msg = await asyncio.wait_for(consumer.getone(), timeout=1.0)
                payload = json.loads(msg.value.decode("utf-8"))

                agent_id = payload.get("agent_id", "unknown_agent")

                # Normalize the top-level payload timestamp
                ts_str = payload.get(
                    "timestamp", datetime.datetime.utcnow().isoformat()
                ).replace("Z", "")
                global_timestamp = datetime.datetime.fromisoformat(ts_str)

                # Extract sub-metrics maps
                metrics = payload.get("metrics", {})
                network = metrics.get("network", {})
                platform = metrics.get("platform", {})
                system = metrics.get("system", {})

                # --- PARSE AND STAGE DEVICE INVENTORY DATA ---
                if network or platform:
                    device_row = (
                        agent_id,
                        str(network.get("hostname", "")),
                        str(network.get("ip-address", "")),
                        str(network.get("mac-address", "")),
                        str(
                            system.get("memory_info", {}).get("total_memory", "Unknown")
                        ),
                        str(platform.get("operating_system", "")),
                        str(platform.get("operating_system_name", "")),
                        str(platform.get("operating_system_version", "")),
                        str(platform.get("operating_system_release", "")),
                        str(
                            platform.get("machine_architecture", "")
                        ),  # Maps custom typo from agent payload Safely
                        1,  # Staging 'is_latest' as True initially
                        global_timestamp,
                    )
                    # Keying by agent_id keeps only the single newest state per agent inside this batch window
                    device_buffer[agent_id] = device_row

                # --- PARSE AND STAGE SECURITY LOGIN ATTEMPTS ---
                login_attempts = platform.get("login_attempts", [])
                for attempt in login_attempts:
                    event_ts_str = attempt.get("timestamp")
                    event_timestamp = (
                        datetime.datetime.fromisoformat(event_ts_str)
                        if event_ts_str
                        else global_timestamp
                    )

                    event_row = (
                        agent_id,
                        event_timestamp,
                        int(attempt.get("event_id", 0)),
                        str(attempt.get("status", "UNKNOWN")),
                        str(attempt.get("username", "unknown")),
                        str(attempt.get("domain", "Unknown")),
                        str(attempt.get("logon_type", "Unknown")),
                        str(attempt.get("source_ip", "Unknown")),
                    )
                    event_buffer.append(event_row)

            except asyncio.TimeoutError:
                # Timeout hit; pass seamlessly to evaluate flushing thresholds below
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
                    rows_to_insert = []

                    for agent_id, device_row in device_buffer.items():
                        try:
                            # Archive existing record versions asynchronously in the background before adding new records
                            db_service.client.command(f"""
                                ALTER TABLE DEVICES 
                                UPDATE is_latest = 0 
                                WHERE agent_id = '{agent_id}' AND is_latest = 1
                            """)
                        except Exception as mutation_err:
                            logger.warning(
                                f"History rotation failed for agent {agent_id}: {mutation_err}"
                            )

                        rows_to_insert.append(device_row)

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
