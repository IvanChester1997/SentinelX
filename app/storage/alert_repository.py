from app.alerts.models import Alert
from app.storage.database import Database


class AlertRepository:
    """Persist and retrieve alerts."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def save(self, alert: Alert) -> Alert:
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    id,
                    incident_id,
                    rule_name,
                    severity,
                    risk_score,
                    risk_level,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.incident_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.risk_score,
                    alert.risk_level.value,
                    alert.status.value,
                    alert.created_at.isoformat(),
                    alert.updated_at.isoformat(),
                ),
            )
        return alert

    def get(self, alert_id: str) -> Alert | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()

        if row is None:
            return None

        return Alert(
            id=row["id"],
            incident_id=row["incident_id"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list(self) -> list[Alert]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY created_at"
            ).fetchall()

        return [
            Alert(
                id=row["id"],
                incident_id=row["incident_id"],
                rule_name=row["rule_name"],
                severity=row["severity"],
                risk_score=row["risk_score"],
                risk_level=row["risk_level"],
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]
