from app.alerts.manager import AlertManager
from app.alerts.models import Alert
from app.api.schemas import EventRequest, EventResponse
from app.detection.engine import DetectionEngine
from app.detection.password_spraying import PasswordSprayingDetector
from app.detection.privilege_escalation import PrivilegeEscalationDetector
from app.detection.privileged_account import PrivilegedAccountDetector
from app.detection.root_login import SuspiciousRootLoginDetector
from app.detection.rules.password_spraying import password_spraying_rule
from app.detection.rules.privilege_escalation import privilege_escalation_rule
from app.detection.rules.privileged_account import privileged_account_rule
from app.detection.rules.root_login import suspicious_root_login_rule
from app.detection.rules.ssh import ssh_bruteforce_rule
from app.events.normalizer import EventNormalizer
from app.incidents.correlation import CorrelationEngine
from app.incidents.models import Incident
from app.risk.engine import RiskEngine
from app.risk.models import RiskAssessment


class MonitoringService:
    """Orchestrate event processing across SentinelX detection layers."""

    def __init__(self) -> None:
        self._detection_engine = DetectionEngine(
            rules=[ssh_bruteforce_rule()],
        )
        self._password_spraying = PasswordSprayingDetector(
            password_spraying_rule(),
        )
        self._privileged_account = PrivilegedAccountDetector(
            privileged_account_rule(),
        )
        self._privilege_escalation = PrivilegeEscalationDetector(
            privilege_escalation_rule(),
        )
        self._root_login = SuspiciousRootLoginDetector(
            suspicious_root_login_rule(),
        )
        self._correlation = CorrelationEngine()
        self._risk = RiskEngine()
        self._alerts = AlertManager()

    def process_event(self, request: EventRequest) -> EventResponse:
        event = EventNormalizer.normalize(request.model_dump(mode="json"))

        matches = self._detection_engine.process(event)
        matches.extend(self._password_spraying.process(event))
        matches.extend(self._privileged_account.process(event))
        matches.extend(self._privilege_escalation.process(event))
        matches.extend(self._root_login.process(event))

        incidents: list[Incident] = []
        risks: list[RiskAssessment] = []
        alerts: list[Alert] = []

        for match in matches:
            incident = self._correlation.process(match)
            risk = self._risk.assess(incident)
            alert = self._alerts.create_or_update(incident, risk)

            incidents.append(incident)
            risks.append(risk)
            alerts.append(alert)

        return EventResponse(
            event_type=event.event_type,
            detection_count=len(matches),
            incidents=incidents,
            risks=risks,
            alerts=alerts,
        )

    def list_incidents(self) -> list[Incident]:
        return self._correlation.list()

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._correlation.get_by_id(incident_id)

    def list_alerts(self) -> list[Alert]:
        return self._alerts.list()

    def get_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def acknowledge_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.acknowledge(alert_id)

    def resolve_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.resolve(alert_id)
