from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
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
