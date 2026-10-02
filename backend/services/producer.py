import asyncio
import json
from aiokafka import AIOKafkaProducer
from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger("producer")


class KafkaProducerService:
    def __init__(self) -> None:
        self.producer = None

    async def start_service(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            acks=1,
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
        await self.producer.send(topic, payload_bytes)

    async def stream_batch(self, topic: str, batch: list):
        """Asynchronously streams a batch of envelopes to Kafka concurrently."""
        if not self.producer:
            raise RuntimeError("Kafka producer is not initialized")
        if not batch:
            return

        tasks = [
            self.producer.send(topic, json.dumps(item).encode("utf-8"))
            for item in batch
        ]
        await asyncio.gather(*tasks)


kafka_service = KafkaProducerService()
