from app.alerts.models import Alert, AlertStatus
from app.incidents.models import Incident
from app.risk.models import RiskAssessment


class AlertManager:
    """Manage the lifecycle of alerts derived from incidents."""

    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}
        self._next_id = 1

    def create(
        self,
        incident: Incident,
        risk: RiskAssessment,
    ) -> Alert:
        alert = Alert(
            id=f"ALT-{self._next_id:06d}",
            incident_id=incident.id,
            rule_name=incident.rule_name,
            severity=incident.severity,
            risk_score=risk.score,
            risk_level=risk.level,
            created_at=incident.last_seen,
            updated_at=incident.last_seen,
        )
        self._next_id += 1
        self._alerts[alert.id] = alert
        return alert

    def create_or_update(
        self,
        incident: Incident,
        risk: RiskAssessment,
    ) -> Alert:
        for alert in self._alerts.values():
            if (
                alert.incident_id == incident.id
                and alert.status != AlertStatus.RESOLVED
            ):
                alert.severity = incident.severity
                alert.risk_score = risk.score
                alert.risk_level = risk.level
                alert.updated_at = incident.last_seen
                return alert

        return self.create(incident, risk)

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def acknowledge(self, alert_id: str) -> Alert | None:
        alert = self.get(alert_id)
        if alert is None or alert.status == AlertStatus.RESOLVED:
            return None

        alert.status = AlertStatus.ACKNOWLEDGED
        return alert

    def resolve(self, alert_id: str) -> Alert | None:
        alert = self.get(alert_id)
        if alert is None:
            return None

        alert.status = AlertStatus.RESOLVED
        return alert
