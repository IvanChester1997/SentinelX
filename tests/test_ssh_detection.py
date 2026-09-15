from datetime import UTC, datetime, timedelta

from app.detection.engine import DetectionEngine
from app.detection.rules.ssh import ssh_bruteforce_rule
from app.events.models import EventSeverity, EventType, NormalizedEvent


def test_ssh_bruteforce_rule_contract() -> None:
    rule = ssh_bruteforce_rule()

    assert rule.name == "ssh_bruteforce"
    assert rule.event_type is EventType.AUTHENTICATION_FAILURE
    assert rule.threshold == 5
    assert rule.window_seconds == 300
    assert rule.group_by == ("source_ip",)
    assert rule.severity is EventSeverity.HIGH


def make_auth_failure(timestamp: datetime, source_ip: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        host="server01",
        source="sshd",
        event_type=EventType.AUTHENTICATION_FAILURE,
        username="root",
        source_ip=source_ip,
        raw="Failed password for root",
    )


def test_ssh_bruteforce_triggers_on_fifth_failure() -> None:
    engine = DetectionEngine([ssh_bruteforce_rule()])
    base = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)

    for index in range(4):
        matches = engine.process(
            make_auth_failure(
                base + timedelta(seconds=index * 30),
                "10.0.0.15",
            )
        )
        assert matches == []

    matches = engine.process(
        make_auth_failure(
            base + timedelta(seconds=120),
            "10.0.0.15",
        )
    )

    assert len(matches) == 1
    assert matches[0].rule_name == "ssh_bruteforce"
    assert matches[0].severity is EventSeverity.HIGH
    assert matches[0].event_count == 5
    assert matches[0].group_key == ("10.0.0.15",)
