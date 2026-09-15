from datetime import timedelta

from app.detection.models import DetectionMatch, DetectionRule
from app.events.models import NormalizedEvent


class PasswordSprayingDetector:
    """Detect authentication failures against multiple users from one source."""

    def __init__(self, rule: DetectionRule, min_unique_users: int = 3) -> None:
        self._rule = rule
        self._min_unique_users = min_unique_users
        self._history: list[NormalizedEvent] = []
        self._last_matches: dict[tuple[str, tuple[str, ...]], object] = {}

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        if event.event_type != self._rule.event_type:
            return []

        self._history.append(event)
        window_start = event.timestamp - timedelta(seconds=self._rule.window_seconds)

        self._history = [
            item
            for item in self._history
            if item.timestamp >= window_start
        ]

        group_key = self._group_key(event)
        matching_events = [
            item
            for item in self._history
            if item.event_type == self._rule.event_type
            and item.timestamp >= window_start
            and self._group_key(item) == group_key
        ]

        unique_users = {
            item.username
            for item in matching_events
            if item.username is not None
        }

        if len(matching_events) < self._rule.threshold:
            return []

        if len(unique_users) < self._min_unique_users:
            return []

        match_key = (self._rule.name, group_key)
        last_match = self._last_matches.get(match_key)

        if last_match is not None:
            if event.timestamp < last_match + timedelta(seconds=self._rule.window_seconds):
                return []
            del self._last_matches[match_key]

        self._last_matches[match_key] = event.timestamp

        return [
            DetectionMatch(
                rule_name=self._rule.name,
                matched_at=event.timestamp,
                event_type=event.event_type,
                severity=self._rule.severity,
                group_key=group_key,
                event_count=len(matching_events),
            )
        ]

    @staticmethod
    def _group_key(event: NormalizedEvent) -> tuple[str, ...]:
        return (str(event.source_ip or ""),)
