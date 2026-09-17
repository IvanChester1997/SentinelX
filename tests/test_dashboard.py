from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_returns_html() -> None:
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "SentinelX" in response.text
    assert "Total Incidents" in response.text
    assert "Total Alerts" in response.text


def test_dashboard_displays_detected_incident_and_alert() -> None:
    event = {
        "timestamp": "2026-09-17T07:00:00Z",
        "host": "dashboard-e2e",
        "source": "sshd",
        "event_type": "authentication_success",
        "username": "root",
        "source_ip": "10.0.0.77",
        "raw": "Accepted publickey for root",
    }

    response = client.post("/api/v1/events", json=event)

    assert response.status_code == 202

    body = response.json()
    incident_id = body["incidents"][0]["id"]
    alert_id = body["alerts"][0]["id"]

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert incident_id in response.text
    assert alert_id in response.text
    assert "suspicious_root_login" in response.text
    assert "high" in response.text
