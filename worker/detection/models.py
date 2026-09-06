"""
worker/detection/models.py

Pydantic dataclasses for detection rule definitions and fired alert payloads.
These are the canonical schemas that flow between the loader, engine, and alerting
dispatcher — ensuring every component speaks the same language.
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ConditionType(str, Enum):
    """The three supported detection condition strategies."""
    THRESHOLD       = "threshold"       # e.g. ≥5 failed logins in 60 s
    PATTERN_MATCH   = "pattern_match"   # e.g. username matches a list
    TIME_WINDOW     = "time_window"     # e.g. login between 22:00–06:00


# ---------------------------------------------------------------------------
# Rule Model — parsed from YAML
# ---------------------------------------------------------------------------

class ThresholdCondition(BaseModel):
    """Params for THRESHOLD rules."""
    field:          str         # Which event field to count/group on (e.g. "source_ip")
    count:          int         # Minimum hits to fire
    window_seconds: int         # Rolling window to count within
    filter_status:  Optional[str] = None   # Only count events with this status (e.g. "FAILURE")


class PatternMatchCondition(BaseModel):
    """Params for PATTERN_MATCH rules."""
    field:   str        # Event field to inspect (e.g. "username", "logon_type")
    values:  List[str]  # Fire if field value is in this list


class TimeWindowCondition(BaseModel):
    """Params for TIME_WINDOW rules — fires on logins outside allowed hours."""
    start_hour: int     # Start of the *alert* window (e.g. 22 = 10 PM)
    end_hour:   int     # End of the alert window   (e.g. 6  = 06 AM)
    filter_status: Optional[str] = None   # Only match events with this status


class DetectionRule(BaseModel):
    """
    A single detection rule loaded from a YAML file.

    Example YAML structure:
        name: brute_force
        description: "..."
        severity: CRITICAL
        enabled: true
        condition:
          type: threshold
          field: source_ip
          count: 5
          window_seconds: 60
          filter_status: FAILURE
    """
    name:        str
    description: str
    severity:    Severity
    enabled:     bool = True
    tags:        List[str] = Field(default_factory=list)
    condition:   Dict[str, Any]   # Raw dict; engine picks the right sub-model

    @field_validator("name")
    @classmethod
    def name_must_be_slug(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError(f"Rule name must be alphanumeric/underscored, got: {v!r}")
        return v.lower()


# ---------------------------------------------------------------------------
# Alert Model — emitted by the engine when a rule fires
# ---------------------------------------------------------------------------

class FiredAlert(BaseModel):
    """
    Represents a single detection hit produced by the engine.
    Passed to the alerting dispatcher and also persisted to ClickHouse.
    """
    rule_name:    str
    severity:     Severity
    agent_id:     str
    triggered_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    message:      str                           # Human-readable summary
    context:      Dict[str, Any]                # Raw event snapshot that triggered the rule
    resolved:     bool = False
