from pathlib import Path

from app.collectors.linux_auth import LinuxAuthLogCollector
from app.services.monitoring import MonitoringService
from app.services.monitoring_worker import MonitoringWorker


def test_ssh_bruteforce_collector_to_alert(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"

    lines = [
        (
            f"Sep 16 16:16:{42 + index * 4:02d} "
            f"sentinel-target sshd[{100 + index}]: "
            f"Failed password for labuser from 172.19.0.1 "
            f"port {37000 + index} ssh2"
        )
        for index in range(5)
    ]

    log_file.write_text("\n".join(lines) + "\n")

    collector = LinuxAuthLogCollector(log_file)
    service = MonitoringService()

    responses = []
    MonitoringWorker(
        collector.collect(),
        service=service,
    ).run(on_response=responses.append)

    assert len(responses) == 5

    assert [response.detection_count for response in responses] == [0, 0, 0, 0, 1]

    final_response = responses[-1]

    assert final_response.event_type.value == "authentication_failure"
    assert len(final_response.incidents) == 1
    assert final_response.incidents[0].rule_name == "ssh_bruteforce"
    assert final_response.incidents[0].status.value == "open"

    assert len(final_response.risks) == 1
    assert final_response.risks[0].severity.value == "high"
    assert final_response.risks[0].score == 75

    assert len(final_response.alerts) == 1
    assert final_response.alerts[0].severity.value == "high"
    assert final_response.alerts[0].status.value == "new"
