from datetime import UTC, datetime, timedelta

from app.detection.engine import DetectionEngine
from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def make_event(
    timestamp: datetime,
    source_ip: str,
    username: str = "root",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host="server01",
        source="sshd",
        event_type=EventType.AUTHENTICATION_FAILURE,
        username=username,
        source_ip=source_ip,
        severity=EventSeverity.MEDIUM,
        raw="Failed password",
    )


def test_detection_triggers_at_threshold() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=3,
        window_seconds=300,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
    engine = DetectionEngine([rule])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert engine.process(make_event(base, "10.0.0.10")) == []
    assert engine.process(make_event(base + timedelta(seconds=30), "10.0.0.10")) == []

    matches = engine.process(make_event(base + timedelta(seconds=60), "10.0.0.10"))

    assert len(matches) == 1
    assert matches[0].rule_name == "ssh_bruteforce"
    assert matches[0].event_count == 3
    assert matches[0].group_key == ("10.0.0.10",)
    assert matches[0].severity is EventSeverity.HIGH


def test_detection_isolated_by_group_key() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=2,
        window_seconds=300,
        group_by=("source_ip",),
    )
    engine = DetectionEngine([rule])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    engine.process(make_event(base, "10.0.0.10"))

    assert engine.process(make_event(base + timedelta(seconds=10), "10.0.0.11")) == []


def test_events_outside_window_do_not_match() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=2,
        window_seconds=60,
        group_by=("source_ip",),
    )
    engine = DetectionEngine([rule])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    engine.process(make_event(base, "10.0.0.10"))

    assert engine.process(
        make_event(base + timedelta(seconds=61), "10.0.0.10")
    ) == []


def test_non_matching_event_type_is_ignored() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=1,
        window_seconds=300,
    )
    engine = DetectionEngine([rule])
    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 15, 17, 0, tzinfo=UTC),
        host="server01",
        source="sshd",
        event_type=EventType.AUTHENTICATION_SUCCESS,
        username="root",
        source_ip="10.0.0.10",
        raw="Accepted publickey",
    )

    assert engine.process(event) == []


def test_detection_does_not_repeat_within_same_threshold_window() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=3,
        window_seconds=300,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
    engine = DetectionEngine([rule])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert engine.process(make_event(base, "10.0.0.10")) == []
    assert engine.process(make_event(base + timedelta(seconds=10), "10.0.0.10")) == []

    first_match = engine.process(make_event(base + timedelta(seconds=20), "10.0.0.10"))
    assert len(first_match) == 1

    assert engine.process(make_event(base + timedelta(seconds=30), "10.0.0.10")) == []
    assert engine.process(make_event(base + timedelta(seconds=40), "10.0.0.10")) == []


def test_detection_can_trigger_again_after_window_expires() -> None:
    rule = DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=2,
        window_seconds=60,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
    engine = DetectionEngine([rule])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert engine.process(make_event(base, "10.0.0.10")) == []
    first_match = engine.process(make_event(base + timedelta(seconds=10), "10.0.0.10"))
    assert len(first_match) == 1

    assert engine.process(make_event(base + timedelta(seconds=30), "10.0.0.10")) == []

    assert engine.process(make_event(base + timedelta(seconds=91), "10.0.0.10")) == []
    second_match = engine.process(make_event(base + timedelta(seconds=100), "10.0.0.10"))

    assert len(second_match) == 1
    assert second_match[0].event_count == 2
