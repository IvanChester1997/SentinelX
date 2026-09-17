from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.api.routes import service

router = APIRouter()
templates = Jinja2Templates(directory="app/dashboard/templates")
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    incidents = service.list_incidents()
    alerts = service.list_alerts()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "incidents": incidents,
            "alerts": alerts,
        },
    )


@router.post("/dashboard/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str) -> RedirectResponse:
    service.acknowledge_alert(alert_id)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.post("/dashboard/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str) -> RedirectResponse:
    service.resolve_alert(alert_id)
    return RedirectResponse(url="/dashboard", status_code=303)
