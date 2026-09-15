from app.detection.models import DetectionRule
from app.events.models import EventSeverity, EventType


def ssh_bruteforce_rule() -> DetectionRule:
    return DetectionRule(
        name="ssh_bruteforce",
        event_type=EventType.AUTHENTICATION_FAILURE,
        threshold=5,
        window_seconds=300,
        group_by=("source_ip",),
        severity=EventSeverity.HIGH,
    )
