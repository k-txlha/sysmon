"""
backend/main.py

Sysmon REST API & Telemetry Gateway.
Provides:
- Telemetry ingestion into Kafka
- ClickHouse security analytics querying (Alerts, Devices, Events)
- Detection Rule management
- Agent token enrollment and health checks
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.v1.agents import router as agents_router
from api.v1.alerts import router as alerts_router
from api.v1.devices import router as devices_router
from api.v1.events import router as events_router
from api.v1.health import router as health_router
from api.v1.rules import router as rules_router
from api.v1.transport import router as transport_router
from config.settings import settings
from services.ch_service import ch_service
from services.producer import kafka_service
from utils.logger import setup_logger

logger = setup_logger("backend_main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Kafka producer and ClickHouse client
    logger.info("Initializing platform backend services...")
    try:
        await kafka_service.start_service()
    except Exception as e:
        logger.warning(f"Kafka service startup warning: {e}")

    try:
        ch_service.connect()
    except Exception as e:
        logger.warning(f"ClickHouse service startup warning: {e}")

    yield

    # Shutdown: Clean up connections
    logger.info("Shutting down platform backend services...")
    try:
        await kafka_service.stop_service()
    except Exception as e:
        logger.warning(f"Kafka service shutdown error: {e}")

    try:
        ch_service.disconnect()
    except Exception as e:
        logger.warning(f"ClickHouse service disconnect error: {e}")


app = FastAPI(
    title="Sysmon Security Platform API",
    description="Open-Source Security Monitoring & Threat Detection Backend API.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for frontend dashboard (Next.js / Vite / React)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(health_router)
app.include_router(transport_router)
app.include_router(alerts_router)
app.include_router(devices_router)
app.include_router(events_router)
app.include_router(rules_router)
app.include_router(agents_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "Sysmon Security Platform API",
        "version": "1.0.0",
        "status": "online",
        "docs": "/docs",
    }


if __name__ == "__main__":
    logger.info(f"Starting Sysmon Backend Gateway on port {settings.PORT}...")
    uvicorn.run("main:app", host="0.0.0.0", port=settings.PORT, reload=True)
