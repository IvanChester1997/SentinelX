
from app.storage.database import Database


def test_memory_database_close_releases_anchor() -> None:
    database = Database(":memory:")

    assert database._memory_anchor is not None

    database.close()

    assert database._memory_anchor is None
