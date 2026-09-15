from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.events.models import EventSeverity


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    level: RiskLevel
    severity: EventSeverity
    detection_count: int = Field(ge=1)
