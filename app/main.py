from fastapi import FastAPI

from app.api.routes import router
from app.core.config import settings
from app.dashboard.routes import router as dashboard_router

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
)

app.include_router(router)
app.include_router(dashboard_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
    }
