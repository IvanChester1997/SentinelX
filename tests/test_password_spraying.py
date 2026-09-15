from datetime import UTC, datetime, timedelta

from app.detection.password_spraying import PasswordSprayingDetector
from app.detection.rules.password_spraying import password_spraying_rule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def make_auth_failure(
    timestamp: datetime,
    username: str,
    source_ip: str = "10.0.0.20",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host="server01",
        source="sshd",
        event_type=EventType.AUTHENTICATION_FAILURE,
        username=username,
        source_ip=source_ip,
        severity=EventSeverity.MEDIUM,
        raw=f"Failed password for {username}",
    )


def test_password_spraying_rule_contract() -> None:
    rule = password_spraying_rule()

    assert rule.name == "password_spraying"
    assert rule.event_type is EventType.AUTHENTICATION_FAILURE
    assert rule.threshold == 5
    assert rule.window_seconds == 300
    assert rule.group_by == ("source_ip",)
    assert rule.severity is EventSeverity.HIGH


def test_password_spraying_triggers_for_multiple_users() -> None:
    detector = PasswordSprayingDetector(password_spraying_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    users = ["alice", "bob", "charlie", "dave", "eve"]

    for index, username in enumerate(users[:-1]):
        assert detector.process(
            make_auth_failure(
                base + timedelta(seconds=index * 30),
                username,
            )
        ) == []

    matches = detector.process(
        make_auth_failure(
            base + timedelta(seconds=120),
            users[-1],
        )
    )

    assert len(matches) == 1
    assert matches[0].rule_name == "password_spraying"
    assert matches[0].severity is EventSeverity.HIGH
    assert matches[0].event_count == 5
    assert matches[0].group_key == ("10.0.0.20",)


def test_password_spraying_does_not_trigger_for_one_user() -> None:
    detector = PasswordSprayingDetector(password_spraying_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    for index in range(5):
        matches = detector.process(
            make_auth_failure(
                base + timedelta(seconds=index * 30),
                "alice",
            )
        )

        assert matches == []


def test_password_spraying_isolated_by_source_ip() -> None:
    detector = PasswordSprayingDetector(password_spraying_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    for index, username in enumerate(["alice", "bob", "charlie", "dave"]):
        assert detector.process(
            make_auth_failure(
                base + timedelta(seconds=index * 30),
                username,
                source_ip="10.0.0.21",
            )
        ) == []

    assert detector.process(
        make_auth_failure(
            base + timedelta(seconds=120),
            "eve",
            source_ip="10.0.0.22",
        )
    ) == []

def test_password_spraying_triggers_again_after_window() -> None:
    detector = PasswordSprayingDetector(password_spraying_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)
    users = ["alice", "bob", "charlie", "dave", "eve"]

    for index, username in enumerate(users):
        matches = detector.process(
            make_auth_failure(
                base + timedelta(seconds=index * 30),
                username,
            )
        )
        assert len(matches) == (0 if index < 4 else 1)

    second_base = base + timedelta(seconds=301)

    for index, username in enumerate(users):
        matches = detector.process(
            make_auth_failure(
                second_base + timedelta(seconds=index * 30),
                username,
            )
        )
        assert len(matches) == (0 if index < 4 else 1)
