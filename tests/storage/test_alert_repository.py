from datetime import UTC, datetime

from app.alerts.models import Alert, AlertStatus
from app.events.models import EventSeverity
from app.risk.models import RiskLevel
from app.storage.alert_repository import AlertRepository
from app.storage.database import Database


def make_alert() -> Alert:
    timestamp = datetime(2026, 9, 15, 17, 10, tzinfo=UTC)
    return Alert(
        id="alert-1",
        incident_id="incident-1",
        rule_name="suspicious_root_login",
        severity=EventSeverity.HIGH,
        risk_score=75,
        risk_level=RiskLevel.HIGH,
        status=AlertStatus.NEW,
        created_at=timestamp,
        updated_at=timestamp,
    )


def test_alert_repository_save_and_get(tmp_path) -> None:
    database = Database(tmp_path / "sentinelx.db")
    repository = AlertRepository(database)
    alert = make_alert()

    repository.save(alert)

    assert repository.get(alert.id) == alert


def test_alert_repository_list(tmp_path) -> None:
    database = Database(tmp_path / "sentinelx.db")
    repository = AlertRepository(database)
    alert = make_alert()

    repository.save(alert)

    assert repository.list() == [alert]
