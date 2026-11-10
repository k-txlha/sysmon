import asyncio
import json
from aiokafka import AIOKafkaProducer

from backend.config.settings import settings
from backend.utils.logger import setup_logger

logger = setup_logger("producer")


class KafkaProducerService:
    def __init__(self) -> None:
        self.producer = None

    async def start_service(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            acks="all",
            enable_idempotence=True,
            compression_type="gzip",
            max_batch_size=65536,
            linger_ms=10,
        )
        await self.producer.start()
        logger.info("Kafka producer initialized and connected.")

    async def stop_service(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka producer stopped cleanly.")

    async def stream_data(self, topic: str, data: dict):
        if not self.producer:
            raise RuntimeError("Kafka producer is not initialized")

        payload_bytes = json.dumps(data).encode("utf-8")
        await self.producer.send_and_wait(topic, payload_bytes)

    async def stream_batch(self, topic: str, batch: list):
        """Wait until every event has been acknowledged by Kafka."""
        if not self.producer:
            raise RuntimeError("Kafka producer is not initialized")
        if not batch:
            return

        tasks = []
        for item in batch:
            agent_id = item.get("agent_id")
            event_id = item.get("event_id")
            if not isinstance(agent_id, str) or not agent_id:
                raise ValueError("Kafka telemetry records require an agent_id.")
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("Kafka telemetry records require an event_id.")
            tasks.append(
                self.producer.send_and_wait(
                    topic,
                    json.dumps(item).encode("utf-8"),
                    key=f"{agent_id}:{event_id}".encode("utf-8"),
                )
            )
        # Stable Kafka keys let downstream consumers recognize duplicate event IDs.
        await asyncio.gather(*tasks)


kafka_service = KafkaProducerService()
