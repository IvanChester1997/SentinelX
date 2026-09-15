from threading import Event

from app.services.monitoring import MonitoringService
from app.services.monitoring_worker import MonitoringWorker


def test_worker_processes_collected_events() -> None:
    events = iter(
        [
            {
                "timestamp": "2026-09-15T17:10:00Z",
                "host": "sentinel",
                "source": "sshd",
                "event_type": "authentication_success",
                "username": "root",
                "source_ip": "10.0.0.50",
                "is_privileged": True,
                "raw": "Accepted publickey for root from 10.0.0.50",
            }
        ]
    )
    service = MonitoringService()
    responses = []

    worker = MonitoringWorker(events, service)
    worker.run(on_response=responses.append)

    assert len(responses) == 1
    assert responses[0].detection_count == 1
    assert responses[0].incidents[0].rule_name == "suspicious_root_login"
    assert responses[0].risks[0].score == 75
    assert responses[0].alerts[0].status == "new"


def test_worker_stops_before_processing_next_event() -> None:
    events = iter(
        [
            {
                "timestamp": "2026-09-15T17:10:00Z",
                "host": "sentinel",
                "source": "sshd",
                "event_type": "authentication_success",
                "username": "root",
                "source_ip": "10.0.0.50",
                "is_privileged": True,
                "raw": "Accepted publickey for root from 10.0.0.50",
            }
        ]
    )
    stop_event = Event()
    stop_event.set()
    responses = []

    worker = MonitoringWorker(events, MonitoringService())
    worker.run(stop_event=stop_event, on_response=responses.append)

    assert responses == []
