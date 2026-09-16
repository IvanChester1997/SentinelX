from pathlib import Path

from app.api.schemas import EventRequest
from app.services.monitoring import MonitoringService


def make_root_login(timestamp: str, source_ip: str = "10.0.0.50") -> EventRequest:
    return EventRequest(
        timestamp=timestamp,
        host="persistent-server",
        source="sshd",
        event_type="authentication_success",
        username="root",
        source_ip=source_ip,
        raw="Accepted publickey for root",
    )


def test_monitoring_service_restores_state_after_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "sentinelx.db"

    first_service = MonitoringService(db_path=db_path)
    first_response = first_service.process_event(
        make_root_login("2026-09-15T17:00:00Z")
    )

    incident_id = first_response.incidents[0].id
    alert_id = first_response.alerts[0].id

    first_service.resolve_alert(alert_id)

    restarted_service = MonitoringService(db_path=db_path)

    restored_incident = restarted_service.get_incident(incident_id)
    restored_alert = restarted_service.get_alert(alert_id)

    assert restored_incident is not None
    assert restored_incident.id == incident_id
    assert restored_incident.rule_name == "suspicious_root_login"

    assert restored_alert is not None
    assert restored_alert.id == alert_id
    assert restored_alert.incident_id == incident_id
    assert restored_alert.status == "resolved"
