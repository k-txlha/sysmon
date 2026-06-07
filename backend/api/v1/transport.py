from fastapi import FastAPI, APIRouter, status, HTTPException
from services.producer import kafka_service
from config.settings import settings
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1")
logger = setup_logger("transport")


@router.post("/telemetry", status_code=status.HTTP_202_ACCEPTED)
async def receive_telemetry(payload: dict):
    if not payload:
        raise HTTPException(status_code=400, detail="Empty payload received.")

    try:
        await kafka_service.stream_data(settings.KAFKA_TOPIC, payload)
        return {"status": "accepted", "message": "Log queued into pipeline."}
    except Exception as e:
        logger.error(f"[ERROR] Failed to push message to Kafka: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Pipeline ingestion failure.",
        )
