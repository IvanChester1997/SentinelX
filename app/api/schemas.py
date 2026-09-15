from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.alerts.models import Alert
from app.events.models import EventSeverity, EventType
from app.incidents.models import Incident
from app.risk.models import RiskAssessment


class EventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    host: str = Field(min_length=1)
    source: str = Field(min_length=1)
    event_type: EventType
    username: str | None = None
    source_ip: str | None = None
    severity: EventSeverity = EventSeverity.INFO
    is_privileged: bool = False
    raw: str = ""


class EventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: EventType
    detection_count: int = Field(ge=0)
    incidents: list[Incident]
    risks: list[RiskAssessment]
    alerts: list[Alert]
