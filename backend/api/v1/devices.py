"""
backend/api/v1/devices.py

REST API router for Device Asset Inventory:
- List all monitored hosts with OS, IP, MAC, architecture, and live status
- Device statistics (online/offline counts, OS breakdown)
- Single device profile details
- Device snapshot audit history
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from services.ch_service import ch_service
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1/devices", tags=["Devices"])
logger = setup_logger("devices_api")


@router.get("", status_code=status.HTTP_200_OK)
async def list_devices():
    """List all registered devices with their latest hardware/OS snapshot and online status."""
    try:
        devices = ch_service.get_devices()
        return {"items": devices, "total": len(devices)}
    except Exception as e:
        logger.error(f"Error fetching devices list: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query device inventory: {str(e)}",
        )


@router.get("/stats", status_code=status.HTTP_200_OK)
async def get_device_statistics():
    """Returns aggregated device inventory metrics (online vs offline, OS distribution)."""
    try:
        return ch_service.get_device_stats()
    except Exception as e:
        logger.error(f"Error fetching device stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate device statistics: {str(e)}",
        )


@router.get("/{agent_id}", status_code=status.HTTP_200_OK)
async def get_device(agent_id: str):
    """Retrieve the latest profile snapshot for a specific agent/device."""
    try:
        device = ch_service.get_device_by_agent_id(agent_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with agent_id '{agent_id}' not found.",
            )
        return device
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching device '{agent_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error while querying device: {str(e)}",
        )


@router.get("/{agent_id}/history", status_code=status.HTTP_200_OK)
async def get_device_history(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=500, description="Max history snapshots"),
):
    """Retrieve historical state snapshots for a specific agent/device."""
    try:
        history = ch_service.get_device_history(agent_id, limit=limit)
        return {"agent_id": agent_id, "history": history, "total": len(history)}
    except Exception as e:
        logger.error(f"Error fetching device history for '{agent_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query device history: {str(e)}",
        )
