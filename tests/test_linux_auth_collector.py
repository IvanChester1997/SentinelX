from datetime import UTC, datetime

from app.collectors.linux_auth import LinuxAuthLogCollector, LinuxAuthLogParser


def test_parser_detects_failed_ssh_authentication() -> None:
    parser = LinuxAuthLogParser(year=2026)

    event = parser.parse_line(
        "Sep 15 17:10:00 sentinel sshd[1234]: "
        "Failed password for root from 10.0.0.50 port 54321 ssh2"
    )

    assert event is not None
    assert event["timestamp"] == datetime(
        2026, 9, 15, 17, 10, tzinfo=UTC
    )
    assert event["host"] == "sentinel"
    assert event["source"] == "sshd"
    assert event["event_type"] == "authentication_failure"
    assert event["username"] == "root"
    assert event["source_ip"] == "10.0.0.50"


def test_parser_detects_successful_root_login() -> None:
    parser = LinuxAuthLogParser(year=2026)

    event = parser.parse_line(
        "Sep 15 17:11:00 sentinel sshd[1234]: "
        "Accepted publickey for root from 10.0.0.50 port 54321 ssh2"
    )

    assert event is not None
    assert event["event_type"] == "authentication_success"
    assert event["username"] == "root"
    assert event["source_ip"] == "10.0.0.50"
    assert event["is_privileged"] is True


def test_parser_ignores_unrelated_lines() -> None:
    parser = LinuxAuthLogParser(year=2026)

    assert parser.parse_line(
        "Sep 15 17:12:00 sentinel systemd[1]: Started some service"
    ) is None


def test_collector_reads_auth_log(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 15 17:10:00 sentinel sshd[1234]: "
        "Failed password for alice from 10.0.0.20 port 54321 ssh2\n"
        "Sep 15 17:11:00 sentinel sshd[1234]: "
        "Accepted publickey for root from 10.0.0.50 port 54321 ssh2\n",
        encoding="utf-8",
    )

    events = list(LinuxAuthLogCollector(log).collect())

    assert len(events) == 2
    assert events[0]["event_type"] == "authentication_failure"
    assert events[1]["event_type"] == "authentication_success"


def test_collector_event_flows_through_monitoring_service(tmp_path) -> None:
    from app.services.monitoring import MonitoringService

    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 15 17:10:00 sentinel sshd[1234]: "
        "Accepted publickey for root from 10.0.0.50 port 54321 ssh2\n",
        encoding="utf-8",
    )

    collector = LinuxAuthLogCollector(log)
    service = MonitoringService()

    events = list(collector.collect())
    response = service.process_collected_event(events[0])

    assert response.detection_count == 1
    assert response.incidents[0].rule_name == "suspicious_root_login"
    assert response.risks[0].score == 75
    assert response.risks[0].level == "high"
    assert response.alerts[0].status == "new"


def test_collector_follow_reads_new_events(tmp_path) -> None:
    from threading import Event, Thread

    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")

    stop_event = Event()
    collector = LinuxAuthLogCollector(log)
    events = collector.follow(
        poll_interval=0.01,
        start_at_end=True,
        stop_event=stop_event,
    )

    result: list[dict[str, object]] = []

    def consume() -> None:
        result.append(next(events))

    thread = Thread(target=consume)
    thread.start()

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            "Sep 15 17:11:00 sentinel sshd[1234]: "
            "Failed password for root from 10.0.0.50 port 54321 ssh2\n"
        )
        handle.flush()

    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result[0]["event_type"] == "authentication_failure"
    assert result[0]["username"] == "root"

    stop_event.set()
    events.close()
