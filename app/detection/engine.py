from app.detection.models import DetectionMatch, DetectionRule
from app.detection.state import DetectionState
from app.events.models import NormalizedEvent


class DetectionEngine:
    """Evaluate normalized events against deterministic threshold rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules
        self._state = DetectionState()

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        self._state.add(event)
        matches: list[DetectionMatch] = []

        for rule in self._rules:
            if event.event_type != rule.event_type:
                continue

            matching_events = [
                item
                for item in self._state.events_in_window(
                    event,
                    rule.window_seconds,
                )
                if item.event_type == rule.event_type
                and self._same_group(item, event, rule)
            ]

            if len(matching_events) < rule.threshold:
                continue

            group_key = self._group_key(event, rule)
            if self._state.is_suppressed(
                rule.name,
                group_key,
                event.timestamp,
                rule.window_seconds,
            ):
                continue

            self._state.record_match(
                rule.name,
                group_key,
                event.timestamp,
            )

            matches.append(
                DetectionMatch(
                    rule_name=rule.name,
                    matched_at=event.timestamp,
                    event_type=event.event_type,
                    severity=rule.severity,
                    group_key=group_key,
                    event_count=len(matching_events),
                )
            )

        return matches

    @staticmethod
    def _group_key(event: NormalizedEvent, rule: DetectionRule) -> tuple[str, ...]:
        return tuple(str(getattr(event, field, "")) for field in rule.group_by)

    @classmethod
    def _same_group(
        cls,
        candidate: NormalizedEvent,
        event: NormalizedEvent,
        rule: DetectionRule,
    ) -> bool:
        return cls._group_key(candidate, rule) == cls._group_key(event, rule)
