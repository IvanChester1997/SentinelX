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


def test_end_to_end_monitoring_flow() -> None:
    event = {
        "timestamp": "2026-09-15T17:10:00Z",
        "host": "e2e-server",
        "source": "sshd",
        "event_type": "authentication_success",
        "username": "root",
        "source_ip": "10.0.0.50",
        "raw": "Accepted publickey for root",
    }

    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 202

    body = response.json()
    assert body["detection_count"] == 1

    incident_id = body["incidents"][0]["id"]
    alert_id = body["alerts"][0]["id"]

    assert body["incidents"][0]["status"] == "open"
    assert body["risks"][0]["score"] == 75
    assert body["risks"][0]["level"] == "high"
    assert body["alerts"][0]["incident_id"] == incident_id
    assert body["alerts"][0]["status"] == "new"

    response = client.get(f"/api/v1/incidents/{incident_id}")
    assert response.status_code == 200
    assert response.json()["id"] == incident_id

    response = client.get(f"/api/v1/alerts/{alert_id}")
    assert response.status_code == 200
    assert response.json()["incident_id"] == incident_id

    response = client.patch(f"/api/v1/alerts/{alert_id}/acknowledge")
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    response = client.patch(f"/api/v1/alerts/{alert_id}/resolve")
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"

    event["timestamp"] = "2026-09-15T17:15:01Z"
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 202

    body = response.json()
    assert body["detection_count"] == 1
    assert body["incidents"][0]["id"] == incident_id
    assert body["alerts"][0]["id"] != alert_id
    assert body["alerts"][0]["incident_id"] == incident_id
    assert body["alerts"][0]["status"] == "new"


def test_end_to_end_password_spraying_detection() -> None:
    users = ["spray-alice", "spray-bob", "spray-charlie", "spray-dave", "spray-eve"]
    source_ip = "10.0.0.60"

    last_body = None

    for index, username in enumerate(users):
        response = client.post(
            "/api/v1/events",
            json={
                "timestamp": f"2026-09-15T17:2{index}:00Z",
                "host": "spray-e2e-server",
                "source": "sshd",
                "event_type": "authentication_failure",
                "username": username,
                "source_ip": source_ip,
                "raw": f"Failed password for {username} from {source_ip}",
            },
        )

        assert response.status_code == 202

        body = response.json()

        if index < 4:
            assert body["detection_count"] == 0
            assert body["incidents"] == []
            assert body["risks"] == []
            assert body["alerts"] == []
        else:
            last_body = body

    assert last_body is not None
    assert last_body["detection_count"] >= 1

    password_spraying = [
        index
        for index, incident in enumerate(last_body["incidents"])
        if incident["rule_name"] == "password_spraying"
    ]

    assert len(password_spraying) == 1

    index = password_spraying[0]
    incident = last_body["incidents"][index]
    risk = last_body["risks"][index]
    alert = last_body["alerts"][index]

    assert incident["severity"] == "high"
    assert incident["status"] == "open"
    assert incident["detection_count"] == 1
    assert incident["group_key"] == [source_ip]

    assert risk["score"] == 75
    assert risk["level"] == "high"
    assert risk["severity"] == "high"

    assert alert["rule_name"] == "password_spraying"
    assert alert["incident_id"] == incident["id"]
    assert alert["risk_score"] == 75
    assert alert["risk_level"] == "high"
    assert alert["status"] == "new"


def test_end_to_end_privilege_escalation_detection() -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-15T18:00:00Z",
            "host": "privilege-e2e-server",
            "source": "auditd",
            "event_type": "privilege_escalation",
            "username": "analyst",
            "source_ip": "10.0.0.70",
            "raw": "sudo: analyst executed privileged command",
        },
    )

    assert response.status_code == 202

    body = response.json()

    matches = [
        index
        for index, incident in enumerate(body["incidents"])
        if incident["rule_name"] == "privilege_escalation"
    ]

    assert len(matches) == 1

    index = matches[0]
    incident = body["incidents"][index]
    risk = body["risks"][index]
    alert = body["alerts"][index]

    assert incident["severity"] == "high"
    assert incident["status"] == "open"
    assert incident["detection_count"] == 1
    assert incident["group_key"] == ["privilege-e2e-server", "analyst"]

    assert risk["score"] == 75
    assert risk["level"] == "high"
    assert risk["severity"] == "high"

    assert alert["rule_name"] == "privilege_escalation"
    assert alert["incident_id"] == incident["id"]
    assert alert["risk_score"] == 75
    assert alert["risk_level"] == "high"
    assert alert["status"] == "new"
