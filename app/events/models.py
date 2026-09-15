from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class EventType(StrEnum):
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_SUCCESS = "authentication_success"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_CREATED = "account_created"
    SECURITY_EVENT = "security_event"


class EventSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    host: str
    source: str
    event_type: EventType
    username: str | None = None
    source_ip: str | None = None
    is_privileged: bool = False
    severity: EventSeverity = EventSeverity.INFO
    raw: str
