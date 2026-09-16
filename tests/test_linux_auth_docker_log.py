from datetime import UTC, datetime
from pathlib import Path

from app.collectors.linux_auth import LinuxAuthLogCollector


def test_collector_parses_docker_ssh_auth_log(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "\n".join(
            [
                "Sep 16 16:13:20 target sshd[10]: "
                "Failed password for labuser from 172.19.0.1 port 40000 ssh2",
                "Sep 16 16:13:27 target sshd[12]: "
                "Accepted password for labuser from 172.19.0.1 port 42974 ssh2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    events = list(LinuxAuthLogCollector(log_path).collect())

    assert len(events) == 2

    assert events[0]["event_type"] == "authentication_failure"
    assert events[0]["username"] == "labuser"
    assert events[0]["source_ip"] == "172.19.0.1"
    assert events[0]["timestamp"] == datetime(
        2026, 9, 16, 16, 13, 20, tzinfo=UTC
    )

    assert events[1]["event_type"] == "authentication_success"
    assert events[1]["username"] == "labuser"
    assert events[1]["source_ip"] == "172.19.0.1"
    assert events[1]["is_privileged"] is False
