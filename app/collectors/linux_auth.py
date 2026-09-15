import re
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

_AUTH_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>sshd)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<source_ip>\S+)"
)

_ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)"
)


class LinuxAuthLogParser:
    """Parse SSH authentication events from Linux auth logs."""

    def __init__(self, year: int | None = None) -> None:
        self._year = year or datetime.now(UTC).year

    def parse_line(self, line: str) -> dict[str, object] | None:
        match = _AUTH_RE.match(line.strip())
        if match is None:
            return None

        message = match.group("message")
        timestamp = datetime.strptime(
            f"{self._year} {match.group('month')} "
            f"{match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=UTC)

        failed = _FAILED_PASSWORD_RE.search(message)
        if failed:
            return {
                "timestamp": timestamp,
                "host": match.group("host"),
                "source": "sshd",
                "event_type": "authentication_failure",
                "username": failed.group("username"),
                "source_ip": failed.group("source_ip"),
                "raw": line.rstrip("\n"),
            }

        accepted = _ACCEPTED_RE.search(message)
        if accepted:
            username = accepted.group("username")
            return {
                "timestamp": timestamp,
                "host": match.group("host"),
                "source": "sshd",
                "event_type": "authentication_success",
                "username": username,
                "source_ip": accepted.group("source_ip"),
                "is_privileged": username == "root",
                "raw": line.rstrip("\n"),
            }

        return None


class LinuxAuthLogCollector:
    """Collect SSH authentication events from a Linux auth log file."""

    def __init__(
        self,
        path: str | Path,
        parser: LinuxAuthLogParser | None = None,
    ) -> None:
        self._path = Path(path)
        self._parser = parser or LinuxAuthLogParser()

    def collect(self) -> Iterator[dict[str, object]]:
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                event = self._parser.parse_line(line)
                if event is not None:
                    yield event

    def follow(
        self,
        poll_interval: float = 0.1,
        start_at_end: bool = True,
        stop_event: object | None = None,
    ) -> Iterator[dict[str, object]]:
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            if start_at_end:
                handle.seek(0, 2)

            while True:
                line = handle.readline()

                if line:
                    event = self._parser.parse_line(line)
                    if event is not None:
                        yield event
                    continue

                if stop_event is not None and stop_event.is_set():
                    return

                time.sleep(poll_interval)
