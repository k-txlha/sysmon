import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager
from api.v1.transport import router
from services.producer import kafka_service
from config.settings import settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start global kafka pool
    await kafka_service.start_service()
    yield
    # Shutdown: Clean up kafka connections
    await kafka_service.stop_service()


app = FastAPI(
    title="SIEM Ingestion Engine",
    description="High-throughput telemetry collector gateway.",
    lifespan=lifespan,
)

app.include_router(router)

if __name__ == "__main__":
    logger.info("Starting SIEM Backend Gateway on port %s...", settings.PORT)
    uvicorn.run("main:app", host="0.0.0.0", port=settings.PORT, reload=True)
