from datetime import UTC, datetime

from app.alerts.manager import AlertManager
from app.alerts.models import AlertStatus
from app.events.models import EventSeverity
from app.incidents.models import Incident
from app.risk.models import RiskAssessment, RiskLevel

BASE_TIME = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)


def make_incident() -> Incident:
    return Incident(
        id="INC-000001",
        rule_name="ssh_bruteforce",
        severity=EventSeverity.HIGH,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        group_key=("10.0.0.10",),
        detection_count=5,
    )


def make_risk() -> RiskAssessment:
    return RiskAssessment(
        score=85,
        level=RiskLevel.HIGH,
        severity=EventSeverity.HIGH,
        detection_count=5,
    )


def test_create_alert() -> None:
    alert = AlertManager().create(make_incident(), make_risk())

    assert alert.id == "ALT-000001"
    assert alert.incident_id == "INC-000001"
    assert alert.rule_name == "ssh_bruteforce"
    assert alert.severity == EventSeverity.HIGH
    assert alert.risk_score == 85
    assert alert.risk_level == RiskLevel.HIGH
    assert alert.status == AlertStatus.NEW
    assert alert.created_at == BASE_TIME
    assert alert.updated_at == BASE_TIME


def test_alert_ids_are_unique() -> None:
    manager = AlertManager()

    first = manager.create(make_incident(), make_risk())
    second = manager.create(
        make_incident().model_copy(update={"id": "INC-000002"}),
        make_risk(),
    )

    assert first.id == "ALT-000001"
    assert second.id == "ALT-000002"


def test_get_returns_alert() -> None:
    manager = AlertManager()
    created = manager.create(make_incident(), make_risk())

    assert manager.get(created.id) == created


def test_acknowledge_changes_status() -> None:
    manager = AlertManager()
    created = manager.create(make_incident(), make_risk())

    alert = manager.acknowledge(created.id)

    assert alert is not None
    assert alert.status == AlertStatus.ACKNOWLEDGED


def test_resolve_changes_status() -> None:
    manager = AlertManager()
    created = manager.create(make_incident(), make_risk())

    alert = manager.resolve(created.id)

    assert alert is not None
    assert alert.status == AlertStatus.RESOLVED


def test_resolved_alert_cannot_be_acknowledged() -> None:
    manager = AlertManager()
    created = manager.create(make_incident(), make_risk())
    manager.resolve(created.id)

    assert manager.acknowledge(created.id) is None


def test_unknown_alert_returns_none() -> None:
    manager = AlertManager()

    assert manager.get("ALT-999999") is None
    assert manager.acknowledge("ALT-999999") is None
    assert manager.resolve("ALT-999999") is None
