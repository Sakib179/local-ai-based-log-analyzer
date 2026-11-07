"""Consistent error envelopes without exposing exception details to clients."""

import logging
import sqlite3
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.schemas import ErrorDetail, ErrorResponse

logger = logging.getLogger("local_ai_security")


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def error_response(
    status_code: int, code: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    body = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=body.model_dump(), headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def application_error(_request: Request, exc: AppError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message)

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException) -> JSONResponse:
        # Framework errors have known messages; never reflect arbitrary exception detail.
        try:
            message = HTTPStatus(exc.status_code).phrase
        except ValueError:
            message = "HTTP request failed."
        return error_response(exc.status_code, f"http_{exc.status_code}", message, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return error_response(422, "validation_error", "Request validation failed.")

    @app.exception_handler(sqlite3.Error)
    async def database_error(request: Request, _exc: sqlite3.Error) -> JSONResponse:
        logger.exception("database_error request_id=%s", request.state.request_id)
        return error_response(503, "database_unavailable", "The local database is unavailable.")
