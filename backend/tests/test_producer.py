import asyncio

import pytest

from backend.services.producer import KafkaProducerService


class RecordingProducer:
    def __init__(self):
        self.records = []

    async def send_and_wait(self, topic, value, key=None):
        self.records.append((topic, value, key))


def test_batch_waits_for_durable_records_and_keys_by_event_identity():
    async def scenario():
        service = KafkaProducerService()
        service.producer = RecordingProducer()

        await service.stream_batch(
            "telemetry",
            [
                {"agent_id": "agent-a", "event_id": "event-1", "data": {}},
                {"agent_id": "agent-a", "event_id": "event-2", "data": {}},
            ],
        )

        assert [record[2] for record in service.producer.records] == [
            b"agent-a:event-1",
            b"agent-a:event-2",
        ]
        assert [record[0] for record in service.producer.records] == [
            "telemetry",
            "telemetry",
        ]

    asyncio.run(scenario())


def test_batch_rejects_missing_event_identity():
    async def scenario():
        service = KafkaProducerService()
        service.producer = RecordingProducer()
        with pytest.raises(ValueError, match="event_id"):
            await service.stream_batch("telemetry", [{"agent_id": "agent-a"}])

    asyncio.run(scenario())
