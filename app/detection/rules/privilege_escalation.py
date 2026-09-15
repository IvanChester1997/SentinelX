from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType


def privilege_escalation_rule() -> DetectionRule:
    return DetectionRule(
        name="privilege_escalation",
        event_type=EventType.PRIVILEGE_ESCALATION,
        threshold=1,
        window_seconds=300,
        group_by=("host", "username"),
        severity=EventSeverity.HIGH,
    )
