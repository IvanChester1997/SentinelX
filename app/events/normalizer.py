from datetime import UTC, datetime
from typing import Any

from app.events.models import EventSeverity, EventType, NormalizedEvent


class EventNormalizer:
    """Convert collector-specific events into the SentinelX event contract."""

    @staticmethod
    def normalize(event: dict[str, Any]) -> NormalizedEvent:
        timestamp = event.get("timestamp")

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        if not isinstance(timestamp, datetime):
            raise ValueError("event timestamp must be a datetime or ISO-8601 string")

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)

        return NormalizedEvent(
            timestamp=timestamp.astimezone(UTC),
            host=str(event["host"]).strip(),
            source=str(event["source"]).strip(),
            event_type=EventType(event["event_type"]),
            username=event.get("username") or None,
            source_ip=event.get("source_ip") or None,
            severity=EventSeverity(event.get("severity", EventSeverity.INFO)),
            raw=str(event.get("raw", "")),
        )
