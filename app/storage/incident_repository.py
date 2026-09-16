import json

from app.incidents.models import Incident
from app.storage.database import Database


class IncidentRepository:
    """Persist and retrieve incidents."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def save(self, incident: Incident) -> Incident:
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    id,
                    rule_name,
                    severity,
                    status,
                    first_seen,
                    last_seen,
                    group_key,
                    detection_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.id,
                    incident.rule_name,
                    incident.severity.value,
                    incident.status.value,
                    incident.first_seen.isoformat(),
                    incident.last_seen.isoformat(),
                    json.dumps(incident.group_key),
                    incident.detection_count,
                ),
            )
        return incident

    def get(self, incident_id: str) -> Incident | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()

        if row is None:
            return None

        return Incident(
            id=row["id"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            status=row["status"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            group_key=tuple(json.loads(row["group_key"])),
            detection_count=row["detection_count"],
        )

    def list(self) -> list[Incident]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY first_seen"
            ).fetchall()

        return [
            Incident(
                id=row["id"],
                rule_name=row["rule_name"],
                severity=row["severity"],
                status=row["status"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                group_key=tuple(json.loads(row["group_key"])),
                detection_count=row["detection_count"],
            )
            for row in rows
        ]
