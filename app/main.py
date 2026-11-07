"""FastAPI application factory and lifespan-managed local resources."""

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from time import gmtime, perf_counter
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.config import APP_NAME, PROJECT_ROOT, Settings
from app.database import Database
from app.inference_database import InferenceStore
from app.event_database import EventStore
from app.errors import error_response, register_error_handlers
from app.routes import analyses, health, pages
from app.services.model import LocalModelService
from app.services.inference import InferenceWorker
from app.services.preparation import PreparationWorker
from app.services.prompts import PromptBuilder
from app.services.correlation import Correlator
from app.services.reporting import ReportService

logger = logging.getLogger("local_ai_security")


def configure_logging(level: str) -> None:
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s")
        formatter.converter = gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.propagate = False


def create_app(
    settings: Settings | None = None,
    *,
    model_transport: httpx.AsyncBaseTransport | None = None,
    prompt_builder: PromptBuilder | None = None,
) -> FastAPI:
    config = settings if settings is not None else Settings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configure_logging(config.log_level)
        config.data_dir.mkdir(parents=True, exist_ok=True)
        assert config.database_path is not None
        database = Database(config.database_path)
        try:
            await run_in_threadpool(database.initialize)
        except Exception:
            logger.exception("database_initialization_failed")
            raise
        application.state.database = database
        uploads_dir = config.data_dir / "uploads"
        uploads_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        async with httpx.AsyncClient(
            base_url=config.model_base_url,
            timeout=httpx.Timeout(config.model_health_timeout_seconds),
            # One generation plus a health/tokenizer request. The inference lock,
            # rather than the pool size, enforces generation exclusivity.
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
            trust_env=False,
            follow_redirects=False,
            transport=model_transport,
        ) as client:
            application.state.model_service = LocalModelService(
                client, config.model_health_timeout_seconds, config.tokenizer_timeout_seconds,
                config.inference_timeout_seconds, config.inference_response_format,
            )
            worker = PreparationWorker(database, application.state.model_service, uploads_dir)
            application.state.preparation_worker = worker
            await run_in_threadpool(worker.recover)
            inference_store = InferenceStore(database)
            application.state.inference_store = inference_store
            event_store = EventStore(database, config)
            application.state.event_store = event_store
            correlator = Correlator(database, event_store, config)
            application.state.report_service = ReportService(database, inference_store, correlator, config)
            application.state.model_service.inference_uncertain = await run_in_threadpool(inference_store.recover)
            inference_worker = InferenceWorker(database, inference_store, application.state.model_service, config, event_store)
            application.state.inference_worker = inference_worker
            worker_task = asyncio.create_task(worker.run(), name="log-preparation")
            inference_task = asyncio.create_task(inference_worker.run(), name="local-inference")
            logger.info("application_started version=%s", __version__)
            try:
                yield
            finally:
                worker_task.cancel()
                inference_task.cancel()
                await asyncio.gather(worker_task, inference_task, return_exceptions=True)
                logger.info("application_stopping")

    application = FastAPI(
        title=APP_NAME,
        version=__version__,
        description="Local security dashboard with sequential inference and cross-chunk security reports.",
        lifespan=lifespan,
        # FastAPI's default documentation loads scripts from a CDN; keep the app offline.
        docs_url=None,
        redoc_url=None,
    )
    application.state.settings = config
    application.state.prompt_builder = prompt_builder or PromptBuilder(model=config.model_alias)
    application.state.templates = Jinja2Templates(directory=PROJECT_ROOT / "app" / "templates")
    register_error_handlers(application)

    @application.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = uuid4().hex
        start = perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("unhandled_error request_id=%s", request.state.request_id)
            response = error_response(500, "internal_error", "An unexpected server error occurred.")
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        route = request.scope.get("route")
        logger.info(
            "request method=%s route=%s status=%s duration_ms=%.1f request_id=%s",
            request.method,
            getattr(route, "path", "unmatched"),
            response.status_code,
            (perf_counter() - start) * 1000,
            request.state.request_id,
        )
        return response

    application.include_router(health.router)
    application.include_router(analyses.router)
    application.include_router(pages.router)
    application.mount(
        "/static", StaticFiles(directory=PROJECT_ROOT / "app" / "static"), name="static"
    )
    return application


app = create_app()
