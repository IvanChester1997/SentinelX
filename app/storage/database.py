import sqlite3
from pathlib import Path
from uuid import uuid4


class Database:
    """Manage the SentinelX SQLite database."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._memory_uri: str | None = None
        self._memory_anchor: sqlite3.Connection | None = None

        if self._path == ":memory:":
            self._memory_uri = f"file:sentinelx_{uuid4().hex}?mode=memory&cache=shared"
            self._memory_anchor = sqlite3.connect(
                self._memory_uri,
                uri=True,
            )
            self._memory_anchor.row_factory = sqlite3.Row

        self._initialize()

    def close(self) -> None:
        if self._memory_anchor is not None:
            self._memory_anchor.close()
            self._memory_anchor = None

    def __del__(self) -> None:
        self.close()

    def connect(self) -> sqlite3.Connection:
        if self._memory_uri is not None:
            connection = sqlite3.connect(self._memory_uri, uri=True)
        else:
            connection = sqlite3.connect(self._path)

        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    group_key TEXT NOT NULL,
                    detection_count INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
