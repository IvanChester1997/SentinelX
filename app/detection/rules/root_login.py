from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType


def suspicious_root_login_rule() -> DetectionRule:
    return DetectionRule(
        name="suspicious_root_login",
        event_type=EventType.AUTHENTICATION_SUCCESS,
        threshold=1,
        window_seconds=300,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
