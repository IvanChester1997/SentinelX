from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType


def privileged_account_rule() -> DetectionRule:
    return DetectionRule(
        name="privileged_account_created",
        event_type=EventType.ACCOUNT_CREATED,
        threshold=1,
        window_seconds=300,
        group_by=("host", "username"),
        severity=EventSeverity.HIGH,
    )
