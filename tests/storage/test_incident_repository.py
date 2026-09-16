from datetime import UTC, datetime

from app.events.models import EventSeverity
from app.incidents.models import Incident, IncidentStatus
from app.storage.database import Database
from app.storage.incident_repository import IncidentRepository


def make_incident() -> Incident:
    timestamp = datetime(2026, 9, 15, 17, 10, tzinfo=UTC)
    return Incident(
        id="incident-1",
        rule_name="suspicious_root_login",
        severity=EventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        first_seen=timestamp,
        last_seen=timestamp,
        group_key=("10.0.0.50",),
        detection_count=1,
    )


def test_incident_repository_save_and_get(tmp_path) -> None:
    database = Database(tmp_path / "sentinelx.db")
    repository = IncidentRepository(database)
    incident = make_incident()

    repository.save(incident)

    assert repository.get(incident.id) == incident


def test_incident_repository_list(tmp_path) -> None:
    database = Database(tmp_path / "sentinelx.db")
    repository = IncidentRepository(database)
    incident = make_incident()

    repository.save(incident)

    assert repository.list() == [incident]
