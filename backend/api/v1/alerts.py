"""
backend/api/v1/alerts.py

REST API router for Threat Detection Alerts:
- List alerts with pagination and rich filtering
- Summary KPI metrics and hourly threat timeline
- Single alert lookup
- Mark alert as resolved / reopen
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from services.ch_service import ch_service
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])
logger = setup_logger("alerts_api")


class ResolveAlertRequest(BaseModel):
    resolved: bool = Field(default=True, description="True to mark resolved, False to reopen.")


@router.get("", status_code=status.HTTP_200_OK)
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    agent_id: Optional[str] = Query(default=None, description="Filter by agent identifier"),
    rule_name: Optional[str] = Query(default=None, description="Filter by detection rule name"),
    resolved: Optional[int] = Query(default=None, ge=0, le=1, description="0 for open alerts, 1 for resolved"),
    start_time: Optional[datetime] = Query(default=None, description="ISO timestamp start filter"),
    end_time: Optional[datetime] = Query(default=None, description="ISO timestamp end filter"),
):
    """List paginated threat detection alerts from ClickHouse with rich filtering."""
    try:
        data = ch_service.get_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            agent_id=agent_id,
            rule_name=rule_name,
            resolved=resolved,
            start_time=start_time,
            end_time=end_time,
        )
        return data
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch alerts from database: {str(e)}",
        )


@router.get("/stats", status_code=status.HTTP_200_OK)
async def get_alert_statistics():
    """Returns aggregated threat KPI stats, breakdown by severity, top rules, and 24h trend."""
    try:
        return ch_service.get_alert_stats()
    except Exception as e:
        logger.error(f"Error fetching alert stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate alert statistics: {str(e)}",
        )


@router.get("/{alert_id}", status_code=status.HTTP_200_OK)
async def get_alert_detail(alert_id: str):
    """Retrieve details and context snapshot for a single alert."""
    try:
        alert = ch_service.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found.",
            )
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching alert detail for {alert_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error while querying alert: {str(e)}",
        )


@router.patch("/{alert_id}/resolve", status_code=status.HTTP_200_OK)
async def resolve_alert(alert_id: str, payload: ResolveAlertRequest = ResolveAlertRequest()):
    """Mark an alert as resolved or reopen it."""
    try:
        success = ch_service.resolve_alert(alert_id, resolved=payload.resolved)
        return {
            "status": "success",
            "alert_id": alert_id,
            "resolved": payload.resolved,
            "message": f"Alert marked as {'resolved' if payload.resolved else 'reopened'}.",
        }
    except Exception as e:
        logger.error(f"Error updating resolution for alert {alert_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert resolution: {str(e)}",
        )
