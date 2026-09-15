from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.events.models import EventSeverity


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    rule_name: str = Field(min_length=1)
    severity: EventSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime
    last_seen: datetime
    group_key: tuple[str, ...] = ()
    detection_count: int = Field(ge=1)
