from app.detection.models import DetectionMatch, DetectionRule
from app.detection.state import DetectionState
from app.events.models import NormalizedEvent


class PasswordSprayingDetector:
    """Detect authentication failures against multiple users from one source."""

    def __init__(self, rule: DetectionRule, min_unique_users: int = 3) -> None:
        self._rule = rule
        self._min_unique_users = min_unique_users
        self._state = DetectionState()

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        if event.event_type != self._rule.event_type:
            return []

        self._state.add(event)

        group_key = self._group_key(event)
        matching_events = [
            item
            for item in self._state.events_in_window(
                event,
                self._rule.window_seconds,
            )
            if item.event_type == self._rule.event_type
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

        if self._state.is_suppressed(
            self._rule.name,
            group_key,
            event.timestamp,
            self._rule.window_seconds,
        ):
            return []

        self._state.record_match(
            self._rule.name,
            group_key,
            event.timestamp,
        )

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
