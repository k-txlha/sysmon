"""
backend/api/v1/events.py

REST API router for Security Event Logs (Windows Event IDs 4624 / 4625):
- Searchable, paginated event query with field-level filters
- Event aggregation statistics (failed vs success, top targets, top attacker IPs)
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from services.ch_service import ch_service
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1/events", tags=["Events"])
logger = setup_logger("events_api")


@router.get("", status_code=status.HTTP_200_OK)
async def list_events(
    limit: int = Query(default=50, ge=1, le=500, description="Max events to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    agent_id: Optional[str] = Query(default=None, description="Filter by agent identifier"),
    event_id: Optional[int] = Query(default=None, description="Filter by Event ID (e.g. 4624, 4625)"),
    username: Optional[str] = Query(default=None, description="Search by username substring"),
    source_ip: Optional[str] = Query(default=None, description="Search by source IP substring"),
    status: Optional[str] = Query(default=None, description="Filter by status: SUCCESS, FAILURE"),
    logon_type: Optional[str] = Query(default=None, description="Filter by Windows logon type (e.g. 2, 3, 10)"),
    start_time: Optional[datetime] = Query(default=None, description="ISO timestamp start filter"),
    end_time: Optional[datetime] = Query(default=None, description="ISO timestamp end filter"),
):
    """Query raw security authentication events with full-text search and filtering."""
    try:
        data = ch_service.get_events(
            limit=limit,
            offset=offset,
            agent_id=agent_id,
            event_id=event_id,
            username=username,
            source_ip=source_ip,
            status=status,
            logon_type=logon_type,
            start_time=start_time,
            end_time=end_time,
        )
        return data
    except Exception as e:
        logger.error(f"Error fetching security events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query events from database: {str(e)}",
        )


@router.get("/stats", status_code=status.HTTP_200_OK)
async def get_event_statistics():
    """Calculates authentication telemetry KPI stats, top failing usernames, and top attacker source IPs."""
    try:
        return ch_service.get_event_stats()
    except Exception as e:
        logger.error(f"Error fetching event stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate event statistics: {str(e)}",
        )
