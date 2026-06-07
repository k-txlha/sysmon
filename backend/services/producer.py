from utils.logger import setup_logger
from aiokafka import AIOKafkaProducer
import asyncio
from config.settings import settings
import json

logger = setup_logger("producer")


class KafkaProducerService:
    def __init__(self) -> None:
        self.producer = None

    async def start_service(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            acks="all",
            compression_type="gzip",
            enable_idempotence=True,
            max_batch_size=65536,
            linger_ms=500,
        )
        await self.producer.start()
        logger.info("Kafka broker is ready to consume records")

    async def stop_service(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka broker stopped!")

    async def stream_data(self, topic: str, data: dict):
        if not self.producer:
            raise RuntimeError("Kafka producer is not initialized")

        payload_bytes = json.dumps(data).encode("utf-8")
        await self.producer.send_and_wait(topic, payload_bytes)


kafka_service = KafkaProducerService()
