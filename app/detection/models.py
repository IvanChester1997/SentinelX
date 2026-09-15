from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.events.models import EventSeverity, EventType


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    event_type: EventType
    threshold: int = Field(ge=1)
    window_seconds: int = Field(gt=0)
    group_by: tuple[str, ...] = ()
    severity: EventSeverity = EventSeverity.MEDIUM


class DetectionMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_name: str
    matched_at: datetime
    event_type: EventType
    severity: EventSeverity
    group_key: tuple[str, ...] = ()
    event_count: int = Field(ge=1)
