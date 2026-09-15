from datetime import UTC, datetime, timedelta

from app.detection.privilege_escalation import PrivilegeEscalationDetector
from app.detection.rules.privilege_escalation import privilege_escalation_rule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def make_privilege_escalation(
    timestamp: datetime,
    username: str = "ivan",
    host: str = "server01",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host=host,
        source="sudo",
        event_type=EventType.PRIVILEGE_ESCALATION,
        username=username,
        severity=EventSeverity.MEDIUM,
        raw="user executed privileged command",
    )


def test_privilege_escalation_rule_contract() -> None:
    rule = privilege_escalation_rule()

    assert rule.name == "privilege_escalation"
    assert rule.event_type is EventType.PRIVILEGE_ESCALATION
    assert rule.threshold == 1
    assert rule.window_seconds == 300
    assert rule.group_by == ("host", "username")
    assert rule.severity is EventSeverity.HIGH


def test_privilege_escalation_triggers() -> None:
    detector = PrivilegeEscalationDetector(privilege_escalation_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    matches = detector.process(make_privilege_escalation(timestamp))

    assert len(matches) == 1
    assert matches[0].rule_name == "privilege_escalation"
    assert matches[0].severity is EventSeverity.HIGH
    assert matches[0].event_count == 1
    assert matches[0].group_key == ("server01", "ivan")


def test_privilege_escalation_ignores_other_event_types() -> None:
    detector = PrivilegeEscalationDetector(privilege_escalation_rule())
    timestamp = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    event = make_privilege_escalation(timestamp).model_copy(
        update={"event_type": EventType.AUTHENTICATION_SUCCESS}
    )

    assert detector.process(event) == []


def test_privilege_escalation_suppresses_same_user_on_same_host() -> None:
    detector = PrivilegeEscalationDetector(privilege_escalation_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_privilege_escalation(base))) == 1
    assert detector.process(
        make_privilege_escalation(
            base + timedelta(seconds=60),
        )
    ) == []


def test_privilege_escalation_isolated_by_user() -> None:
    detector = PrivilegeEscalationDetector(privilege_escalation_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(
        detector.process(
            make_privilege_escalation(base, username="ivan")
        )
    ) == 1

    matches = detector.process(
        make_privilege_escalation(
            base + timedelta(seconds=60),
            username="alex",
        )
    )

    assert len(matches) == 1
    assert matches[0].group_key == ("server01", "alex")


def test_privilege_escalation_triggers_again_after_window() -> None:
    detector = PrivilegeEscalationDetector(privilege_escalation_rule())
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    assert len(detector.process(make_privilege_escalation(base))) == 1
    assert len(
        detector.process(
            make_privilege_escalation(
                base + timedelta(seconds=301),
            )
        )
    ) == 1
