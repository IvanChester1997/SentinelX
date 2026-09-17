from fastapi.testclient import TestClient

from app.main import app


def test_dashboard_returns_html() -> None:
    client = TestClient(app)

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "SentinelX" in response.text
    assert "Total Incidents" in response.text
    assert "Total Alerts" in response.text
