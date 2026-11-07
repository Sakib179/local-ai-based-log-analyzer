"""Server-rendered initial application page."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.config import APP_NAME

router = APIRouter(include_in_schema=False)


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": APP_NAME,
            "model_alias": settings.model_alias,
            "model_base_url": settings.model_base_url,
            "context_tokens": settings.model_context_tokens,
            "max_upload_bytes": settings.max_upload_bytes,
        },
    )
