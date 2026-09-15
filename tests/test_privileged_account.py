from datetime import UTC, datetime, timedelta

from app.detection.privileged_account import PrivilegedAccountDetector
from app.detection.rules.privileged_account import privileged_account_rule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def make_account_created(
    timestamp: datetime,
    username: str = "backdoor",
    is_privileged: bool = True,
    host: str = "server01",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host=host,
        source="useradd",
        event_type=EventType.ACCOUNT_CREATED,
        username=username,
        is_privileged=is_privileged,
        severity=EventSeverity.MEDIUM,
        raw="Created account",
    )


def test_privileged_account_rule_contract() -> None:
    rule = privileged_account_rule()

    assert rule.name == "privileged_account_created"
    assert rule.event_type is EventType.ACCOUNT_CREATED
    assert rule.threshold == 1
    assert rule.window_seconds == 300
    assert rule.group_by == ("host", "username")
    assert rule.severity is EventSeverity.HIGH


def test_privileged_account_triggers() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    matches = detector.process(make_account_created(timestamp))

    assert len(matches) == 1
    assert matches[0].rule_name == "privileged_account_created"
    assert matches[0].severity is EventSeverity.HIGH
    assert matches[0].event_count == 1
    assert matches[0].group_key == ("server01", "backdoor")


def test_non_privileged_account_is_ignored() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert detector.process(
        make_account_created(timestamp, is_privileged=False)
    ) == []


def test_other_event_type_is_ignored() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    event = make_account_created(timestamp).model_copy(
        update={"event_type": EventType.AUTHENTICATION_SUCCESS}
    )

    assert detector.process(event) == []


def test_privileged_account_suppresses_duplicate() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_account_created(base))) == 1
    assert detector.process(
        make_account_created(base + timedelta(seconds=60))
    ) == []


def test_privileged_accounts_are_isolated_by_user() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(
        detector.process(
            make_account_created(base, username="backdoor")
        )
    ) == 1

    matches = detector.process(
        make_account_created(
            base + timedelta(seconds=60),
            username="another",
        )
    )

    assert len(matches) == 1
    assert matches[0].group_key == ("server01", "another")


def test_privileged_account_triggers_again_after_window() -> None:
    detector = PrivilegedAccountDetector(privileged_account_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_account_created(base))) == 1
    assert len(
        detector.process(
            make_account_created(base + timedelta(seconds=301))
        )
    ) == 1
