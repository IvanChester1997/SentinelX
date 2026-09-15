from datetime import timedelta

from app.detection.models import DetectionMatch, DetectionRule
from app.events.models import NormalizedEvent


class DetectionEngine:
    """Evaluate normalized events against deterministic threshold rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules
        self._history: list[NormalizedEvent] = []
        self._last_matches: dict[tuple[str, tuple[str, ...]], object] = {}

    def process(self, event: NormalizedEvent) -> list[DetectionMatch]:
        self._history.append(event)
        matches: list[DetectionMatch] = []

        for rule in self._rules:
            if event.event_type != rule.event_type:
                continue

            window_start = event.timestamp - timedelta(seconds=rule.window_seconds)
            self._history = [
                item
                for item in self._history
                if item.timestamp >= window_start
            ]

            matching_events = [
                item
                for item in self._history
                if item.event_type == rule.event_type
                and item.timestamp >= window_start
                and self._same_group(item, event, rule)
            ]

            if len(matching_events) < rule.threshold:
                continue

            group_key = self._group_key(event, rule)
            match_key = (rule.name, group_key)
            last_match = self._last_matches.get(match_key)

            if last_match is not None:
                if event.timestamp < last_match + timedelta(seconds=rule.window_seconds):
                    continue
                del self._last_matches[match_key]

            self._last_matches[match_key] = event.timestamp

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
