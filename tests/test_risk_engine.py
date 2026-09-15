from datetime import UTC, datetime

import pytest

from app.events.models import EventSeverity
from app.incidents.models import Incident
from app.risk.engine import RiskEngine
from app.risk.models import RiskLevel

BASE_TIME = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)


def make_incident(
    *,
    severity: EventSeverity = EventSeverity.HIGH,
    detection_count: int = 1,
) -> Incident:
    return Incident(
        id="INC-000001",
        rule_name="ssh_bruteforce",
        severity=severity,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        group_key=("10.0.0.10",),
        detection_count=detection_count,
    )


@pytest.mark.parametrize(
    ("severity", "expected_score", "expected_level"),
    [
        (EventSeverity.INFO, 10, RiskLevel.LOW),
        (EventSeverity.LOW, 25, RiskLevel.LOW),
        (EventSeverity.MEDIUM, 50, RiskLevel.MEDIUM),
        (EventSeverity.HIGH, 75, RiskLevel.HIGH),
        (EventSeverity.CRITICAL, 100, RiskLevel.CRITICAL),
    ],
)
def test_base_risk_by_severity(
    severity: EventSeverity,
    expected_score: int,
    expected_level: RiskLevel,
) -> None:
    result = RiskEngine().assess(make_incident(severity=severity))

    assert result.score == expected_score
    assert result.level == expected_level


def test_repeated_detection_increases_score() -> None:
    result = RiskEngine().assess(
        make_incident(
            severity=EventSeverity.HIGH,
            detection_count=3,
        )
    )

    assert result.score == 85
    assert result.level == RiskLevel.HIGH


def test_repetition_bonus_is_capped() -> None:
    result = RiskEngine().assess(
        make_incident(
            severity=EventSeverity.MEDIUM,
            detection_count=100,
        )
    )

    assert result.score == 75
    assert result.level == RiskLevel.HIGH


def test_score_is_capped_at_100() -> None:
    result = RiskEngine().assess(
        make_incident(
            severity=EventSeverity.CRITICAL,
            detection_count=100,
        )
    )

    assert result.score == 100
    assert result.level == RiskLevel.CRITICAL


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, RiskLevel.LOW),
        (39, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (69, RiskLevel.MEDIUM),
        (70, RiskLevel.HIGH),
        (89, RiskLevel.HIGH),
        (90, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(
    score: int,
    expected_level: RiskLevel,
) -> None:
    assert RiskEngine._level_for(score) == expected_level
