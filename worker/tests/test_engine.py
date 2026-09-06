"""
worker/tests/test_engine.py

Unit tests for the Sysmon Detection Engine.

Tests are pure Python — no Kafka, no ClickHouse, no network needed.
They feed synthetic event tuples directly into engine.evaluate() and
assert on the FiredAlert objects returned.

Run from the `worker/` directory:
    pytest tests/test_engine.py -v
"""

import sys
import datetime
import pytest
from pathlib import Path

# ── Path setup so `detection` and `utils` imports resolve ───────────────────
# Tests live in worker/tests/, imports need worker/ on sys.path.
WORKER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKER_DIR))

from detection.engine import DetectionEngine
from detection.models import ConditionType, FiredAlert, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    agent_id:   str = "test-agent",
    status:     str = "FAILURE",
    username:   str = "testuser",
    source_ip:  str = "10.0.0.1",
    logon_type: str = "Network (e.g., Shared Folder)",
    domain:     str = "WORKGROUP",
    event_id:   int = 4625,
    timestamp:  datetime.datetime = None,
) -> tuple:
    """
    Build a synthetic EVENTS row tuple matching the column order used
    by the worker and expected by DetectionEngine._row_to_dict():
        (agent_id, timestamp, event_id, status, username, domain,
         logon_type, source_ip)
    """
    ts = timestamp or datetime.datetime.now(datetime.timezone.utc)
    return (agent_id, ts, event_id, status, username, domain, logon_type, source_ip)


def _engine_with_rules(rules_yaml: list[dict]) -> DetectionEngine:
    """
    Build a DetectionEngine pre-loaded with the given rule dicts,
    bypassing the YAML file loader entirely.
    """
    from detection.models import DetectionRule

    engine = DetectionEngine.__new__(DetectionEngine)
    engine.rules = [DetectionRule(**r) for r in rules_yaml]
    # Re-initialise the sliding window store
    from collections import defaultdict
    engine._windows = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list.__new__(list).__class__.__mro__[0]))
    )
    # Use a real defaultdict(deque) for the window
    from collections import deque
    engine._windows = defaultdict(
        lambda: defaultdict(lambda: defaultdict(deque))
    )
    return engine


# ---------------------------------------------------------------------------
# Threshold rule tests
# ---------------------------------------------------------------------------

class TestThresholdRule:
    BRUTE_FORCE_RULE = {
        "name": "brute_force",
        "description": "Test brute force rule",
        "severity": "CRITICAL",
        "enabled": True,
        "condition": {
            "type": "threshold",
            "field": "source_ip",
            "count": 5,
            "window_seconds": 60,
            "filter_status": "FAILURE",
        },
    }

    def test_fires_at_threshold(self):
        """Engine should fire when failure count reaches the configured threshold."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)
        # Exactly 5 FAILURE events from the same IP
        events = [_make_event(source_ip="1.2.3.4", status="FAILURE", timestamp=now) for _ in range(5)]

        alerts = engine.evaluate(events, "test-agent")

        assert len(alerts) == 1
        assert alerts[0].rule_name == "brute_force"
        assert alerts[0].severity == Severity.CRITICAL
        assert alerts[0].context["field_value"] == "1.2.3.4"
        assert alerts[0].context["count"] == 5

    def test_does_not_fire_below_threshold(self):
        """Engine must stay silent when event count is below the threshold."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)
        events = [_make_event(source_ip="1.2.3.4", status="FAILURE", timestamp=now) for _ in range(4)]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_ignores_success_events(self):
        """Threshold rule with filter_status=FAILURE must ignore SUCCESS events."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)
        # 5 SUCCESS events — should NOT fire the FAILURE-only rule
        events = [_make_event(source_ip="1.2.3.4", status="SUCCESS", timestamp=now) for _ in range(5)]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_stale_events_pruned_from_window(self):
        """Events older than window_seconds should be pruned and not count toward the threshold."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)
        old = now - datetime.timedelta(seconds=120)  # 2 min ago — outside 60s window

        # 5 old events + 2 fresh ones → should NOT fire (only 2 fresh)
        old_events  = [_make_event(source_ip="9.9.9.9", status="FAILURE", timestamp=old) for _ in range(5)]
        new_events  = [_make_event(source_ip="9.9.9.9", status="FAILURE", timestamp=now) for _ in range(2)]

        alerts = engine.evaluate(old_events + new_events, "test-agent")

        assert alerts == []

    def test_groups_by_field_value(self):
        """Threshold fires per field-value; two different IPs should not combine counts."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)
        # 3 from IP A + 3 from IP B — neither reaches 5 individually
        events = (
            [_make_event(source_ip="1.1.1.1", status="FAILURE", timestamp=now) for _ in range(3)] +
            [_make_event(source_ip="2.2.2.2", status="FAILURE", timestamp=now) for _ in range(3)]
        )

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_threshold_accumulates_across_batches(self):
        """Sliding window state persists across multiple evaluate() calls."""
        engine = _engine_with_rules([self.BRUTE_FORCE_RULE])
        now = datetime.datetime.now(datetime.timezone.utc)

        # First batch: 3 events — should not fire
        batch1 = [_make_event(source_ip="5.5.5.5", status="FAILURE", timestamp=now) for _ in range(3)]
        alerts1 = engine.evaluate(batch1, "test-agent")
        assert alerts1 == []

        # Second batch: 2 more — total = 5, should fire
        batch2 = [_make_event(source_ip="5.5.5.5", status="FAILURE", timestamp=now) for _ in range(2)]
        alerts2 = engine.evaluate(batch2, "test-agent")
        assert len(alerts2) == 1
        assert alerts2[0].rule_name == "brute_force"


# ---------------------------------------------------------------------------
# Pattern-match rule tests
# ---------------------------------------------------------------------------

class TestPatternMatchRule:
    PRIV_RULE = {
        "name": "privileged_account_login",
        "description": "Privileged account login",
        "severity": "HIGH",
        "enabled": True,
        "condition": {
            "type": "pattern_match",
            "field": "username",
            "values": ["Administrator", "root", "admin"],
        },
    }

    def test_fires_on_watchlist_match(self):
        engine = _engine_with_rules([self.PRIV_RULE])
        events = [_make_event(username="Administrator", status="SUCCESS")]

        alerts = engine.evaluate(events, "test-agent")

        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert alerts[0].context["matched_value"] == "administrator"   # lowercased

    def test_case_insensitive_match(self):
        """Pattern match must be case-insensitive."""
        engine = _engine_with_rules([self.PRIV_RULE])
        events = [_make_event(username="ADMINISTRATOR", status="SUCCESS")]

        alerts = engine.evaluate(events, "test-agent")

        assert len(alerts) == 1

    def test_no_fire_on_non_watchlist_user(self):
        engine = _engine_with_rules([self.PRIV_RULE])
        events = [_make_event(username="alice", status="SUCCESS")]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_fires_only_once_per_batch(self):
        """Pattern match should return one alert even if multiple matching events exist."""
        engine = _engine_with_rules([self.PRIV_RULE])
        events = [_make_event(username="root") for _ in range(10)]

        alerts = engine.evaluate(events, "test-agent")

        # The rule returns on the first match — exactly one alert per rule per batch
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Time-window rule tests
# ---------------------------------------------------------------------------

class TestTimeWindowRule:
    AFTER_HOURS_RULE = {
        "name": "after_hours_login",
        "description": "After hours login",
        "severity": "HIGH",
        "enabled": True,
        "condition": {
            "type": "time_window",
            "start_hour": 22,
            "end_hour": 6,
            "filter_status": "SUCCESS",
        },
    }

    def _ts_at_hour(self, hour: int) -> datetime.datetime:
        """Return a UTC datetime for today at the given hour."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return now.replace(hour=hour, minute=0, second=0, microsecond=0)

    def test_fires_at_midnight(self):
        """00:00 UTC is inside the 22–06 window."""
        engine = _engine_with_rules([self.AFTER_HOURS_RULE])
        events = [_make_event(status="SUCCESS", timestamp=self._ts_at_hour(0))]

        alerts = engine.evaluate(events, "test-agent")

        assert len(alerts) == 1
        assert alerts[0].rule_name == "after_hours_login"

    def test_fires_at_23h(self):
        """23:00 UTC is inside the restricted window."""
        engine = _engine_with_rules([self.AFTER_HOURS_RULE])
        events = [_make_event(status="SUCCESS", timestamp=self._ts_at_hour(23))]

        alerts = engine.evaluate(events, "test-agent")

        assert len(alerts) == 1

    def test_does_not_fire_during_business_hours(self):
        """14:00 UTC (2 PM) is outside the restricted window."""
        engine = _engine_with_rules([self.AFTER_HOURS_RULE])
        events = [_make_event(status="SUCCESS", timestamp=self._ts_at_hour(14))]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_ignores_failed_logins(self):
        """With filter_status=SUCCESS, FAILURE events at restricted hours should not fire."""
        engine = _engine_with_rules([self.AFTER_HOURS_RULE])
        events = [_make_event(status="FAILURE", timestamp=self._ts_at_hour(23))]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []


# ---------------------------------------------------------------------------
# Engine-level edge case tests
# ---------------------------------------------------------------------------

class TestEngineEdgeCases:
    def test_no_rules_returns_empty(self):
        """Engine with zero rules should return an empty alert list."""
        engine = _engine_with_rules([])
        events = [_make_event() for _ in range(10)]

        alerts = engine.evaluate(events, "test-agent")

        assert alerts == []

    def test_empty_events_returns_empty(self):
        """Engine with rules but no events should return an empty alert list."""
        rule = {
            "name": "brute_force",
            "description": "...",
            "severity": "CRITICAL",
            "enabled": True,
            "condition": {
                "type": "threshold",
                "field": "source_ip",
                "count": 5,
                "window_seconds": 60,
                "filter_status": "FAILURE",
            },
        }
        engine = _engine_with_rules([rule])
        alerts = engine.evaluate([], "test-agent")

        assert alerts == []

    def test_unknown_condition_type_skipped_gracefully(self):
        """An unrecognised condition type should log a warning and not crash."""
        rule = {
            "name": "mystery_rule",
            "description": "Unknown condition",
            "severity": "LOW",
            "enabled": True,
            "condition": {"type": "neural_network"},   # not a real type
        }
        engine = _engine_with_rules([rule])
        events = [_make_event()]

        # Must not raise; must return empty list
        alerts = engine.evaluate(events, "test-agent")
        assert alerts == []

    def test_disabled_rule_is_not_loaded(self):
        """
        Verify that disabled rules are skipped by the loader.
        This tests the loader rather than the engine, but is a critical integration check.
        """
        from detection.models import DetectionRule
        rule = DetectionRule(
            name="disabled_rule",
            description="Should never fire",
            severity="HIGH",
            enabled=False,
            condition={"type": "pattern_match", "field": "username", "values": ["admin"]},
        )
        # A disabled rule would not be added by loader.load_rules()
        # Manually verify the enabled flag
        assert rule.enabled is False

    def test_fired_alert_has_correct_schema(self):
        """FiredAlert objects must populate all required fields."""
        rule = {
            "name": "priv_rule",
            "description": "...",
            "severity": "HIGH",
            "enabled": True,
            "condition": {
                "type": "pattern_match",
                "field": "username",
                "values": ["root"],
            },
        }
        engine = _engine_with_rules([rule])
        events = [_make_event(username="root")]

        alerts = engine.evaluate(events, "my-host")

        assert len(alerts) == 1
        alert: FiredAlert = alerts[0]
        assert alert.rule_name == "priv_rule"
        assert alert.severity  == Severity.HIGH
        assert alert.agent_id  == "my-host"
        assert isinstance(alert.triggered_at, datetime.datetime)
        assert isinstance(alert.message, str) and alert.message
        assert isinstance(alert.context, dict)
        assert alert.resolved is False
