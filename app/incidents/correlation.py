from app.detection.models import DetectionMatch
from app.incidents.models import Incident, IncidentStatus


class CorrelationEngine:
    """Correlate detection matches into lifecycle-managed incidents."""

    def __init__(self) -> None:
        self._incidents: dict[tuple[str, tuple[str, ...]], Incident] = {}
        self._next_id = 1

    def process(self, match: DetectionMatch) -> Incident:
        key = (match.rule_name, match.group_key)
        incident = self._incidents.get(key)

        if incident is None or incident.status == IncidentStatus.RESOLVED:
            incident = Incident(
                id=f"INC-{self._next_id:06d}",
                rule_name=match.rule_name,
                severity=match.severity,
                first_seen=match.matched_at,
                last_seen=match.matched_at,
                group_key=match.group_key,
                detection_count=1,
            )
            self._next_id += 1
            self._incidents[key] = incident
            return incident

        incident.last_seen = match.matched_at
        incident.detection_count += 1

        if match.severity.value > incident.severity.value:
            incident.severity = match.severity

        return incident

    def list(self) -> list[Incident]:
        return list(self._incidents.values())

    def get_by_id(self, incident_id: str) -> Incident | None:
        return next(
            (incident for incident in self._incidents.values() if incident.id == incident_id),
            None,
        )

    def get(self, rule_name: str, group_key: tuple[str, ...]) -> Incident | None:
        return self._incidents.get((rule_name, group_key))

    def acknowledge(self, rule_name: str, group_key: tuple[str, ...]) -> Incident | None:
        incident = self.get(rule_name, group_key)
        if incident is None or incident.status == IncidentStatus.RESOLVED:
            return None

        incident.status = IncidentStatus.ACKNOWLEDGED
        return incident

    def resolve(self, rule_name: str, group_key: tuple[str, ...]) -> Incident | None:
        incident = self.get(rule_name, group_key)
        if incident is None:
            return None

        incident.status = IncidentStatus.RESOLVED
        return incident
