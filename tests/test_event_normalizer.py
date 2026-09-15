from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.events.models import EventSeverity, EventType
from app.events.normalizer import EventNormalizer


def test_normalize_authentication_failure() -> None:
    event = EventNormalizer.normalize(
        {
            "timestamp": "2026-09-15T17:00:00Z",
            "host": "server01",
            "source": "sshd",
            "event_type": "authentication_failure",
            "username": "root",
            "source_ip": "10.10.10.15",
            "severity": "medium",
            "raw": "Failed password for root",
        }
    )

    assert event.timestamp == datetime(2026, 9, 15, 17, 0, tzinfo=UTC)
    assert event.event_type is EventType.AUTHENTICATION_FAILURE
    assert event.severity is EventSeverity.MEDIUM
    assert event.username == "root"
    assert event.source_ip == "10.10.10.15"


def test_normalize_naive_timestamp_as_utc() -> None:
    event = EventNormalizer.normalize(
        {
            "timestamp": datetime(2026, 9, 15, 17, 0),
            "host": "server01",
            "source": "sshd",
            "event_type": "authentication_success",
            "raw": "Accepted publickey",
        }
    )

    assert event.timestamp == datetime(2026, 9, 15, 17, 0, tzinfo=UTC)


def test_normalize_defaults_optional_fields() -> None:
    event = EventNormalizer.normalize(
        {
            "timestamp": "2026-09-15T17:00:00Z",
            "host": "server01",
            "source": "sshd",
            "event_type": "security_event",
        }
    )

    assert event.username is None
    assert event.source_ip is None
    assert event.severity is EventSeverity.INFO
    assert event.raw == ""


def test_invalid_event_type_is_rejected() -> None:
    with pytest.raises(ValueError):
        EventNormalizer.normalize(
            {
                "timestamp": "2026-09-15T17:00:00Z",
                "host": "server01",
                "source": "sshd",
                "event_type": "unknown_event",
            }
        )


def test_normalized_event_rejects_extra_fields() -> None:
    from app.events.models import NormalizedEvent

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(
            {
                "timestamp": "2026-09-15T17:00:00Z",
                "host": "server01",
                "source": "sshd",
                "event_type": "security_event",
                "unexpected": "value",
            }
        )


def test_normalize_privileged_account_flag() -> None:
    event = EventNormalizer.normalize(
        {
            "timestamp": "2026-09-15T17:00:00Z",
            "host": "server01",
            "source": "useradd",
            "event_type": "account_created",
            "username": "backdoor",
            "is_privileged": True,
            "raw": "Created privileged account",
        }
    )

    assert event.is_privileged is True


def test_normalize_privileged_account_flag_defaults_false() -> None:
    event = EventNormalizer.normalize(
        {
            "timestamp": "2026-09-15T17:00:00Z",
            "host": "server01",
            "source": "useradd",
            "event_type": "account_created",
            "username": "ivan",
        }
    )

    assert event.is_privileged is False
