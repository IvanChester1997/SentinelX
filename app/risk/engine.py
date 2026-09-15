from app.events.models import EventSeverity
from app.incidents.models import Incident
from app.risk.models import RiskAssessment, RiskLevel


class RiskEngine:
    """Calculate deterministic risk scores for security incidents."""

    _SEVERITY_SCORES = {
        EventSeverity.INFO: 10,
        EventSeverity.LOW: 25,
        EventSeverity.MEDIUM: 50,
        EventSeverity.HIGH: 75,
        EventSeverity.CRITICAL: 100,
    }

    def assess(self, incident: Incident) -> RiskAssessment:
        base_score = self._SEVERITY_SCORES[incident.severity]
        repetition_bonus = min((incident.detection_count - 1) * 5, 25)
        score = min(base_score + repetition_bonus, 100)

        return RiskAssessment(
            score=score,
            level=self._level_for(score),
            severity=incident.severity,
            detection_count=incident.detection_count,
        )

    @staticmethod
    def _level_for(score: int) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        if score >= 70:
            return RiskLevel.HIGH
        if score >= 40:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
