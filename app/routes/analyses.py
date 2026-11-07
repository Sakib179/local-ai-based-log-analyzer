"""Streaming upload acceptance and bounded inspection of preparation results."""

import json
from dataclasses import asdict
from uuid import UUID, uuid4

from fastapi import APIRouter, Query, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from fastapi.responses import StreamingResponse

from app.errors import AppError
from app.schemas import AnalysisCreated, AnalysisResponse, AnalysisStarted, ChunkDetail, ChunkPage, ErrorResponse
from app.services.security_prompts import SECURITY_SYSTEM_PROMPT
from app.services.uploads import UploadReceiver, multipart_boundary, receive_upload

router = APIRouter(prefix="/api/analyses", tags=["analyses"])


@router.post(
    "", status_code=202, response_model=AnalysisCreated,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 415: {"model": ErrorResponse}},
    openapi_extra={"requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
        "type": "object", "required": ["file"],
        "properties": {"file": {"type": "string", "format": "binary"}},
    }}}}},
)
async def upload_analysis(request: Request) -> AnalysisCreated:
    settings = request.app.state.settings
    boundary = multipart_boundary(request, settings.max_upload_bytes)
    database = request.app.state.database
    analysis_id = str(uuid4())
    uploads_dir = settings.data_dir / "uploads"
    temporary = uploads_dir / f"{analysis_id}.part"
    destination = uploads_dir / f"{analysis_id}.log"
    config = {"prompt": asdict(request.app.state.prompt_builder), "context_tokens": settings.model_context_tokens}
    await run_in_threadpool(database.create_analysis, analysis_id, destination, config)
    try:
        receiver = await run_in_threadpool(UploadReceiver, temporary, settings.max_upload_bytes, boundary)
        await receive_upload(request, receiver)
        await run_in_threadpool(temporary.replace, destination)
        await run_in_threadpool(
            database.queue_analysis, analysis_id, receiver.filename, receiver.size, receiver.hash.hexdigest()
        )
    except BaseException as exc:
        # A cancellation after the queue commit must not remove an accepted job's file.
        job = await run_in_threadpool(database.get_analysis, analysis_id)
        if job is not None and job["status"] == "uploading":
            await run_in_threadpool(temporary.unlink, missing_ok=True)
            await run_in_threadpool(destination.unlink, missing_ok=True)
            if isinstance(exc, AppError):
                code, message = exc.code, exc.message
            else:
                code, message = "upload_failed", "The upload did not complete."
            await run_in_threadpool(database.fail_analysis, analysis_id, code, message)
        if isinstance(exc, ClientDisconnect):
            raise AppError(400, "upload_interrupted", "The upload was interrupted.") from None
        if isinstance(exc, OSError):
            raise AppError(503, "storage_error", "The upload could not be stored.") from None
        raise
    finally:
        request.app.state.preparation_worker.wakeup.set()
    return AnalysisCreated(id=analysis_id)


async def _analysis(request: Request, analysis_id: UUID) -> dict:
    job = await run_in_threadpool(request.app.state.database.get_analysis, str(analysis_id))
    if job is None:
        raise AppError(404, "analysis_not_found", "Analysis not found.")
    return job


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def analysis_status(request: Request, analysis_id: UUID) -> dict:
    job = await _analysis(request, analysis_id)
    progress = await run_in_threadpool(request.app.state.inference_store.progress, str(analysis_id))
    job["preparation_status"] = job["status"]
    job["inference"] = progress
    job["error"] = (
        {"code": job["error_code"], "message": job["error_message"]} if job["error_code"] else None
    )
    if progress:
        job["status"] = progress["status"]
        job["error"] = progress["error"]
        job["updated_at"] = progress["updated_at"]
    return job


@router.post("/{analysis_id}/start", status_code=202, response_model=AnalysisStarted)
async def start_analysis(request: Request, analysis_id: UUID) -> AnalysisStarted:
    job = await _analysis(request, analysis_id)
    settings = request.app.state.settings
    preparation = json.loads(job["preparation_config"])
    config = {
        "model": settings.model_alias, "system_prompt": SECURITY_SYSTEM_PROMPT,
        "context_tokens": min(settings.model_context_tokens, preparation["context_tokens"], 2048),
        "saved_context": preparation["prompt"].get("saved_context", "")[:512],
    }
    status = await run_in_threadpool(request.app.state.inference_store.queue, str(analysis_id), config)
    request.app.state.inference_worker.wakeup.set()
    return AnalysisStarted(id=str(analysis_id), status=status)


@router.get("/{analysis_id}/chunks", response_model=ChunkPage)
async def list_chunks(
    request: Request, analysis_id: UUID,
    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
) -> dict:
    job = await _analysis(request, analysis_id)
    chunks = await run_in_threadpool(
        request.app.state.database.list_chunks, str(analysis_id), limit, offset
    )
    for chunk in chunks:
        chunk["inference"] = await run_in_threadpool(request.app.state.inference_store.chunk_progress, chunk["id"])
    return {"chunks": chunks, "total": job["total_chunks"], "limit": limit, "offset": offset}


@router.get("/{analysis_id}/chunks/{chunk_id}", response_model=ChunkDetail)
async def get_chunk(request: Request, analysis_id: UUID, chunk_id: UUID) -> dict:
    await _analysis(request, analysis_id)
    chunk = await run_in_threadpool(request.app.state.database.get_chunk, str(analysis_id), str(chunk_id))
    if chunk is None:
        raise AppError(404, "chunk_not_found", "Chunk not found.")
    chunk["inference"] = await run_in_threadpool(request.app.state.inference_store.chunk_progress, str(chunk_id))
    return chunk


@router.get("/{analysis_id}/findings")
async def list_findings(request: Request, analysis_id: UUID,
                        limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict:
    await _analysis(request, analysis_id)
    progress = await run_in_threadpool(request.app.state.inference_store.progress, str(analysis_id))
    findings = await run_in_threadpool(request.app.state.inference_store.list_findings, str(analysis_id), limit, offset)
    return {"findings": findings, "total": progress["findings_count"] if progress else 0,
            "limit": limit, "offset": offset, "assessment": "Model-generated suspicions with verified citations; not confirmed attacks."}


@router.get("/{analysis_id}/attempts")
async def list_attempts(request: Request, analysis_id: UUID,
                        limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict:
    await _analysis(request, analysis_id)
    attempts = await run_in_threadpool(request.app.state.inference_store.list_attempts, str(analysis_id), limit, offset)
    return {"attempts": attempts, "limit": limit, "offset": offset}


@router.get("/{analysis_id}/report", response_class=StreamingResponse,
            responses={200: {"content": {"application/json": {}}}})
async def security_report(request: Request, analysis_id: UUID, download: bool = False) -> StreamingResponse:
    await _analysis(request, analysis_id)
    await run_in_threadpool(request.app.state.report_service.prepare, str(analysis_id))
    headers = {"Content-Disposition": f'attachment; filename="security-report-{analysis_id}.json"'} if download else None
    return StreamingResponse(request.app.state.report_service.stream(str(analysis_id)), media_type="application/json", headers=headers)
