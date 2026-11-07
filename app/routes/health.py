"""Backend readiness and independent model availability checks."""

from fastapi import APIRouter, Request

from app import __version__
from app.errors import AppError
from app.schemas import ErrorResponse, HealthResponse, ModelHealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, responses={503: {"model": ErrorResponse}})
def backend_health(request: Request) -> HealthResponse:
    if not request.app.state.database.is_healthy():
        raise AppError(503, "database_unavailable", "The local database is unavailable.")
    return HealthResponse(version=__version__)


@router.get(
    "/api/model/health",
    response_model=ModelHealthResponse,
    responses={503: {"model": ErrorResponse}},
)
async def model_health(request: Request) -> ModelHealthResponse:
    await request.app.state.model_service.check_health()
    return ModelHealthResponse(model=request.app.state.settings.model_alias)
