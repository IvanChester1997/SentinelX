from datetime import UTC, datetime, timedelta

from app.detection.state import DetectionState
from app.events.models import EventType, NormalizedEvent


def make_event(timestamp: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host="server01",
        source="sshd",
        event_type=EventType.AUTHENTICATION_FAILURE,
        source_ip="10.0.0.10",
        raw="Failed password",
    )


def test_events_in_window_removes_old_events() -> None:
    state = DetectionState()
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    state.add(make_event(base))
    state.add(make_event(base + timedelta(seconds=30)))

    events = state.events_in_window(
        make_event(base + timedelta(seconds=61)),
        window_seconds=60,
    )

    assert len(events) == 1
    assert events[0].timestamp == base + timedelta(seconds=30)


def test_match_is_suppressed_inside_window() -> None:
    state = DetectionState()
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)
    group_key = ("10.0.0.10",)

    state.record_match("ssh_bruteforce", group_key, timestamp)

    assert state.is_suppressed(
        "ssh_bruteforce",
        group_key,
        timestamp + timedelta(seconds=30),
        60,
    )


def test_match_is_allowed_after_window() -> None:
    state = DetectionState()
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)
    group_key = ("10.0.0.10",)

    state.record_match("ssh_bruteforce", group_key, timestamp)

    assert not state.is_suppressed(
        "ssh_bruteforce",
        group_key,
        timestamp + timedelta(seconds=61),
        60,
    )
