from datetime import UTC, datetime, timedelta

from app.detection.root_login import SuspiciousRootLoginDetector
from app.detection.rules.root_login import suspicious_root_login_rule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def make_auth_success(
    timestamp: datetime,
    username: str = "root",
    source: str = "sshd",
    source_ip: str = "10.0.0.30",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host="server01",
        source=source,
        event_type=EventType.AUTHENTICATION_SUCCESS,
        username=username,
        source_ip=source_ip,
        raw=f"Accepted publickey for {username}",
    )


def test_suspicious_root_login_rule_contract() -> None:
    rule = suspicious_root_login_rule()

    assert rule.name == "suspicious_root_login"
    assert rule.event_type is EventType.AUTHENTICATION_SUCCESS
    assert rule.threshold == 1
    assert rule.window_seconds == 300
    assert rule.group_by == ("source_ip",)
    assert rule.severity is EventSeverity.HIGH


def test_suspicious_root_login_triggers() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    matches = detector.process(make_auth_success(timestamp))

    assert len(matches) == 1
    assert matches[0].rule_name == "suspicious_root_login"
    assert matches[0].severity is EventSeverity.HIGH
    assert matches[0].event_count == 1
    assert matches[0].group_key == ("10.0.0.30",)


def test_suspicious_root_login_ignores_non_root_user() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert detector.process(
        make_auth_success(timestamp, username="ivan")
    ) == []


def test_suspicious_root_login_ignores_non_ssh_source() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert detector.process(
        make_auth_success(timestamp, source="sudo")
    ) == []


def test_suspicious_root_login_suppresses_same_source_within_window() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_auth_success(base))) == 1
    assert detector.process(
        make_auth_success(base + timedelta(seconds=60))
    ) == []


def test_suspicious_root_login_allows_different_source() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(
        detector.process(
            make_auth_success(base, source_ip="10.0.0.30")
        )
    ) == 1

    matches = detector.process(
        make_auth_success(
            base + timedelta(seconds=60),
            source_ip="10.0.0.31",
        )
    )

    assert len(matches) == 1
    assert matches[0].group_key == ("10.0.0.31",)


def test_suspicious_root_login_triggers_again_after_window() -> None:
    detector = SuspiciousRootLoginDetector(suspicious_root_login_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_auth_success(base))) == 1
    assert len(
        detector.process(
            make_auth_success(base + timedelta(seconds=301))
        )
    ) == 1
