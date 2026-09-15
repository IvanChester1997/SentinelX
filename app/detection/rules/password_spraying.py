from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType


def password_spraying_rule() -> DetectionRule:
    return DetectionRule(
        name="password_spraying",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=5,
        window_seconds=300,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
