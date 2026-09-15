from fastapi import APIRouter, HTTPException, status

from app.alerts.models import Alert
from app.api.schemas import EventRequest, EventResponse
from app.incidents.models import Incident
from app.services.monitoring import MonitoringService

router = APIRouter(prefix="/api/v1")
service = MonitoringService()


@router.post(
    "/events",
    response_model=EventResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def process_event(request: EventRequest) -> EventResponse:
    return service.process_event(request)


@router.get("/incidents", response_model=list[Incident])
def list_incidents() -> list[Incident]:
    return service.list_incidents()


@router.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    incident = service.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        )
    return incident


@router.get("/alerts", response_model=list[Alert])
def list_alerts() -> list[Alert]:
    return service.list_alerts()


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str) -> Alert:
    alert = service.get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="alert not found",
        )
    return alert


@router.patch("/alerts/{alert_id}/acknowledge", response_model=Alert)
def acknowledge_alert(alert_id: str) -> Alert:
    alert = service.acknowledge_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="alert not found or already resolved",
        )
    return alert


@router.patch("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str) -> Alert:
    alert = service.resolve_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="alert not found",
        )
    return alert
