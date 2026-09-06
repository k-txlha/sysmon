"""
worker/detection/engine.py

The core detection engine.  After each Kafka batch is parsed, the worker
calls `engine.evaluate(events, agent_id)` which runs every loaded rule
against the batch and returns a list of FiredAlert objects.

Three condition strategies are supported:

  THRESHOLD     — fire if a field value appears ≥N times (within a time
                  window, tracked per agent_id) with an optional status filter.
                  Example: ≥5 FAILURE events from the same source_ip in 60 s.

  PATTERN_MATCH — fire if a field's value is contained in a predefined list.
                  Example: username in ["admin", "root", "Administrator"].

  TIME_WINDOW   — fire if an event's timestamp falls between two hours-of-day.
                  Example: any SUCCESS login between 22:00 and 06:00.

State for THRESHOLD rules is maintained in an in-memory sliding-window dict
(keyed by agent_id → field_value → deque of timestamps).  This is intentionally
kept in-process to keep the MVP dependency-free; a Redis-backed version is the
natural next step for multi-worker deployments.
"""

from __future__ import annotations

import datetime
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from .loader import load_rules
from .models import (
    ConditionType,
    DetectionRule,
    FiredAlert,
    PatternMatchCondition,
    Severity,
    ThresholdCondition,
    TimeWindowCondition,
)
from utils.logger import setup_logger

logger = setup_logger("detection_engine")


# ---------------------------------------------------------------------------
# Internal type aliases
# ---------------------------------------------------------------------------

# sliding_window[agent_id][rule_name][field_value] = deque of UTC datetimes
_SlidingWindow = Dict[str, Dict[str, Dict[str, deque]]]


class DetectionEngine:
    """
    Stateful detection engine that evaluates parsed event batches against
    all enabled detection rules.

    Usage in worker/main.py:
        engine = DetectionEngine()
        ...
        alerts = engine.evaluate(event_rows, agent_id)
    """

    def __init__(self) -> None:
        self.rules: List[DetectionRule] = load_rules()
        # Sliding window state: agent → rule → field_value → timestamps
        self._windows: _SlidingWindow = defaultdict(
            lambda: defaultdict(lambda: defaultdict(deque))
        )
        logger.info(
            f"DetectionEngine initialized with {len(self.rules)} active rule(s)."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self, events: List[tuple], agent_id: str
    ) -> List[FiredAlert]:
        """
        Evaluate a batch of parsed event rows against all loaded rules.

        `events` is a list of tuples in the same order as the EVENTS table:
            (agent_id, timestamp, event_id, status, username, domain,
             logon_type, source_ip)

        Returns a (possibly empty) list of FiredAlert objects.
        """
        if not self.rules or not events:
            return []

        # Normalise raw tuples into dicts for readable rule evaluation
        event_dicts = [self._row_to_dict(row) for row in events]

        fired: List[FiredAlert] = []

        for rule in self.rules:
            condition_type = rule.condition.get("type", "").lower()
            try:
                if condition_type == ConditionType.THRESHOLD:
                    alert = self._evaluate_threshold(rule, event_dicts, agent_id)
                elif condition_type == ConditionType.PATTERN_MATCH:
                    alert = self._evaluate_pattern_match(rule, event_dicts, agent_id)
                elif condition_type == ConditionType.TIME_WINDOW:
                    alert = self._evaluate_time_window(rule, event_dicts, agent_id)
                else:
                    logger.warning(
                        f"Rule '{rule.name}' has unknown condition type '{condition_type}' — skipping."
                    )
                    alert = None

                if alert:
                    fired.append(alert)
                    logger.warning(
                        f"🚨 [{alert.severity.value}] Rule fired: '{alert.rule_name}' "
                        f"on agent '{agent_id}' — {alert.message}"
                    )

            except Exception as exc:
                logger.error(
                    f"Error evaluating rule '{rule.name}' for agent '{agent_id}': {exc}"
                )

        return fired

    # ------------------------------------------------------------------
    # Condition evaluators
    # ------------------------------------------------------------------

    def _evaluate_threshold(
        self,
        rule: DetectionRule,
        events: List[Dict[str, Any]],
        agent_id: str,
    ) -> Optional[FiredAlert]:
        """
        Count how many times a field value appears (within the sliding window)
        and fire if it exceeds the threshold.
        """
        cond = ThresholdCondition(**rule.condition)
        window_secs = cond.window_seconds
        field = cond.field
        min_count = cond.count
        filter_status = cond.filter_status

        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(seconds=window_secs)

        # Per-agent, per-rule window bucket
        window_bucket = self._windows[agent_id][rule.name]

        # Accumulate timestamps from this batch into the sliding window
        for event in events:
            if filter_status and event.get("status", "").upper() != filter_status.upper():
                continue

            field_value = str(event.get(field, ""))
            if not field_value or field_value in ("unknown", "Unknown", "-", ""):
                continue

            ts = event.get("timestamp")
            if not isinstance(ts, datetime.datetime):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)

            window_bucket[field_value].append(ts)

        # Prune stale entries and check threshold
        best_field_value = None
        best_count = 0

        for field_value, timestamps in window_bucket.items():
            # Remove timestamps outside the rolling window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) > best_count:
                best_count = len(timestamps)
                best_field_value = field_value

        if best_count >= min_count:
            return FiredAlert(
                rule_name=rule.name,
                severity=rule.severity,
                agent_id=agent_id,
                triggered_at=now,
                message=(
                    f"{best_count} events on field '{field}={best_field_value}' "
                    f"within {window_secs}s (threshold: {min_count})"
                ),
                context={
                    "field": field,
                    "field_value": best_field_value,
                    "count": best_count,
                    "window_seconds": window_secs,
                    "filter_status": filter_status,
                },
            )

        return None

    def _evaluate_pattern_match(
        self,
        rule: DetectionRule,
        events: List[Dict[str, Any]],
        agent_id: str,
    ) -> Optional[FiredAlert]:
        """
        Fire if any event's field value is in the rule's predefined value list.
        """
        cond = PatternMatchCondition(**rule.condition)
        field = cond.field
        watch_values = {v.lower() for v in cond.values}

        for event in events:
            field_value = str(event.get(field, "")).lower()
            if field_value in watch_values:
                return FiredAlert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    agent_id=agent_id,
                    triggered_at=datetime.datetime.now(datetime.timezone.utc),
                    message=(
                        f"Field '{field}' matched watchlist value '{field_value}'"
                    ),
                    context={
                        "field": field,
                        "matched_value": field_value,
                        "watchlist": list(cond.values),
                        "event_snapshot": {
                            k: str(v) for k, v in event.items() if k != "timestamp"
                        },
                    },
                )

        return None

    def _evaluate_time_window(
        self,
        rule: DetectionRule,
        events: List[Dict[str, Any]],
        agent_id: str,
    ) -> Optional[FiredAlert]:
        """
        Fire if any event occurred during the restricted time-of-day window.
        Handles windows that span midnight (e.g. 22:00 – 06:00).
        """
        cond = TimeWindowCondition(**rule.condition)
        start_h = cond.start_hour
        end_h = cond.end_hour
        filter_status = cond.filter_status

        for event in events:
            if filter_status and event.get("status", "").upper() != filter_status.upper():
                continue

            ts = event.get("timestamp")
            if not isinstance(ts, datetime.datetime):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)

            hour = ts.hour

            # Determine if the hour falls inside the restricted window.
            # A window like 22–06 spans midnight, so we invert the check.
            if start_h < end_h:
                # Normal window (e.g. 08–18): fire if hour is inside
                in_window = start_h <= hour < end_h
            else:
                # Midnight-spanning window (e.g. 22–06): fire if hour is outside business hours
                in_window = hour >= start_h or hour < end_h

            if in_window:
                return FiredAlert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    agent_id=agent_id,
                    triggered_at=datetime.datetime.now(datetime.timezone.utc),
                    message=(
                        f"Login event at {ts.strftime('%H:%M UTC')} falls within "
                        f"restricted window ({start_h:02d}:00–{end_h:02d}:00 UTC)"
                    ),
                    context={
                        "event_hour_utc": hour,
                        "restricted_window": f"{start_h:02d}:00–{end_h:02d}:00 UTC",
                        "username": event.get("username"),
                        "status": event.get("status"),
                        "source_ip": event.get("source_ip"),
                        "timestamp": ts.isoformat(),
                    },
                )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: tuple) -> Dict[str, Any]:
        """
        Convert a raw EVENTS table tuple to a named dict.
        Tuple order mirrors insert_events_batch() in ch_client.py:
            (agent_id, timestamp, event_id, status, username,
             domain, logon_type, source_ip)
        """
        keys = [
            "agent_id", "timestamp", "event_id", "status",
            "username", "domain", "logon_type", "source_ip",
        ]
        return dict(zip(keys, row))
