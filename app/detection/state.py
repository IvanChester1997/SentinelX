from datetime import datetime, timedelta

from app.events.models import NormalizedEvent


class DetectionState:
    """Maintain event history and suppress repeated matches."""

    def __init__(self) -> None:
        self._history: list[NormalizedEvent] = []
        self._last_matches: dict[tuple[str, tuple[str, ...]], datetime] = {}

    def add(self, event: NormalizedEvent) -> None:
        self._history.append(event)

    def events_in_window(
        self,
        event: NormalizedEvent,
        window_seconds: int,
    ) -> list[NormalizedEvent]:
        window_start = event.timestamp - timedelta(seconds=window_seconds)

        self._history = [
            item
            for item in self._history
            if item.timestamp >= window_start
        ]

        return [
            item
            for item in self._history
            if item.timestamp >= window_start
        ]

    def is_suppressed(
        self,
        rule_name: str,
        group_key: tuple[str, ...],
        timestamp: datetime,
        window_seconds: int,
    ) -> bool:
        match_key = (rule_name, group_key)
        last_match = self._last_matches.get(match_key)

        if last_match is None:
            return False

        if timestamp < last_match + timedelta(seconds=window_seconds):
            return True

        del self._last_matches[match_key]
        return False

    def record_match(
        self,
        rule_name: str,
        group_key: tuple[str, ...],
        timestamp: datetime,
    ) -> None:
        self._last_matches[(rule_name, group_key)] = timestamp
