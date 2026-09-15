from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_event_api_creates_alert_for_root_login() -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-15T17:00:00Z",
            "host": "server01",
            "source": "sshd",
            "event_type": "authentication_success",
            "username": "root",
            "source_ip": "10.0.0.10",
            "raw": "Accepted publickey for root",
        },
    )

    assert response.status_code == 202

    body = response.json()
    assert body["detection_count"] == 1
    assert body["incidents"][0]["rule_name"] == "suspicious_root_login"
    assert body["risks"][0]["score"] == 75
    assert body["alerts"][0]["status"] == "new"


def test_alert_lifecycle_api() -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-15T17:01:00Z",
            "host": "server02",
            "source": "sshd",
            "event_type": "authentication_success",
            "username": "root",
            "source_ip": "10.0.0.20",
            "raw": "Accepted publickey for root",
        },
    )

    alert_id = response.json()["alerts"][0]["id"]

    response = client.patch(f"/api/v1/alerts/{alert_id}/acknowledge")
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    response = client.patch(f"/api/v1/alerts/{alert_id}/resolve")
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_unknown_alert_returns_404() -> None:
    response = client.get("/api/v1/alerts/ALT-999999")

    assert response.status_code == 404


def test_incident_list_and_get_api() -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-15T17:02:00Z",
            "host": "server03",
            "source": "sshd",
            "event_type": "authentication_success",
            "username": "root",
            "source_ip": "10.0.0.30",
            "raw": "Accepted publickey for root",
        },
    )

    assert response.status_code == 202
    incident_id = response.json()["incidents"][0]["id"]

    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    assert any(incident["id"] == incident_id for incident in response.json())

    response = client.get(f"/api/v1/incidents/{incident_id}")
    assert response.status_code == 200
    assert response.json()["id"] == incident_id


def test_unknown_incident_returns_404() -> None:
    response = client.get("/api/v1/incidents/INC-999999")

    assert response.status_code == 404


def test_alert_list_api() -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-15T17:03:00Z",
            "host": "server04",
            "source": "sshd",
            "event_type": "authentication_success",
            "username": "root",
            "source_ip": "10.0.0.40",
            "raw": "Accepted publickey for root",
        },
    )

    assert response.status_code == 202
    alert_id = response.json()["alerts"][0]["id"]

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert any(alert["id"] == alert_id for alert in response.json())
