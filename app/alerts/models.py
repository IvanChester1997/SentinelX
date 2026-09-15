from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.events.models import EventSeverity
from app.risk.models import RiskLevel


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    rule_name: str = Field(min_length=1)
    severity: EventSeverity
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime
    updated_at: datetime
