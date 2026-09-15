from app.detection.models import DetectionMatch, DetectionRule
from app.detection.state import DetectionState
from app.events.models import NormalizedEvent


class PrivilegedAccountDetector:
    """Detect creation of accounts explicitly marked as privileged."""

    def __init__(self, rule: DetectionRule) -> None:
        self._rule = rule
        self._state = DetectionState()

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        if event.event_type != self._rule.event_type:
            return []

        if not event.is_privileged:
            return []

        self._state.add(event)

        group_key = self._group_key(event)

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
                event_count=1,
            )
        ]

    @staticmethod
    def _group_key(event: NormalizedEvent) -> tuple[str, ...]:
        return (event.host, str(event.username or ""))
