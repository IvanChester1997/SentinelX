from datetime import UTC, datetime, timedelta

from app.detection.models import DetectionMatch
from app.events.models import EventSeverity, EventType
from app.incidents.correlation import CorrelationEngine
from app.incidents.models import IncidentStatus

BASE_TIME = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)


def make_match(
    *,
    rule_name: str = "ssh_bruteforce",
    source_ip: str = "10.0.0.10",
    matched_at: datetime = BASE_TIME,
    severity: EventSeverity = EventSeverity.HIGH,
) -> DetectionMatch:
    return DetectionMatch(
        rule_name=rule_name,
        matched_at=matched_at,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=severity,
        group_key=(source_ip,),
        event_count=5,
    )


def test_first_match_creates_open_incident() -> None:
    incident = CorrelationEngine().process(make_match())

    assert incident.id == "INC-000001"
    assert incident.status == IncidentStatus.OPEN
    assert incident.detection_count == 1
    assert incident.first_seen == BASE_TIME
    assert incident.last_seen == BASE_TIME


def test_same_rule_and_group_updates_existing_incident() -> None:
    engine = CorrelationEngine()

    first = engine.process(make_match())
    second = engine.process(
        make_match(matched_at=BASE_TIME + timedelta(seconds=30))
    )

    assert second.id == first.id
    assert second.detection_count == 2
    assert second.last_seen == BASE_TIME + timedelta(seconds=30)


def test_different_group_creates_separate_incident() -> None:
    engine = CorrelationEngine()

    first = engine.process(make_match(source_ip="10.0.0.10"))
    second = engine.process(make_match(source_ip="10.0.0.20"))

    assert first.id != second.id


def test_acknowledge_changes_status() -> None:
    engine = CorrelationEngine()
    engine.process(make_match())

    incident = engine.acknowledge("ssh_bruteforce", ("10.0.0.10",))

    assert incident is not None
    assert incident.status == IncidentStatus.ACKNOWLEDGED


def test_resolve_changes_status() -> None:
    engine = CorrelationEngine()
    engine.process(make_match())

    incident = engine.resolve("ssh_bruteforce", ("10.0.0.10",))

    assert incident is not None
    assert incident.status == IncidentStatus.RESOLVED


def test_match_after_resolution_creates_new_incident() -> None:
    engine = CorrelationEngine()
    first = engine.process(make_match())
    engine.resolve("ssh_bruteforce", ("10.0.0.10",))

    second = engine.process(
        make_match(matched_at=BASE_TIME + timedelta(minutes=10))
    )

    assert second.id != first.id
    assert second.id == "INC-000002"
    assert second.status == IncidentStatus.OPEN


def test_get_returns_existing_incident() -> None:
    engine = CorrelationEngine()
    created = engine.process(make_match())

    found = engine.get("ssh_bruteforce", ("10.0.0.10",))

    assert found == created


def test_resolved_incident_can_be_acknowledged_no_longer() -> None:
    engine = CorrelationEngine()
    engine.process(make_match())
    engine.resolve("ssh_bruteforce", ("10.0.0.10",))

    assert engine.acknowledge("ssh_bruteforce", ("10.0.0.10",)) is None
