"""One durable inference worker: bounded plans, verified candidates, safe checkpoints."""

import asyncio
import hashlib
import json
import logging
import sqlite3
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from time import perf_counter

from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.database import Database
from app.errors import AppError
from app.inference_database import InferenceStore
from app.event_database import EventStore
from app.services.chunking import Chunker, PreparedChunk
from app.services.findings import InvalidFindingResponse, evidence_from_records, parse_findings, validate_evidence, verify_original
from app.services.model import LocalModelService, ModelCallError
from app.services.parsing import Evidence
from app.services.prompts import OUTPUT_TOKENS, SAFETY_TOKENS
from app.services.security_prompts import SecurityPromptBuilder

logger = logging.getLogger("local_ai_security")
STOP_CODES = {
    "model_unavailable", "model_timeout", "model_connection_error", "model_state_uncertain",
    "model_server_error", "tokenizer_unavailable", "tokenizer_timeout", "storage_error", "evidence_changed",
}


class InferenceWorker:
    def __init__(self, database: Database, store: InferenceStore, model: LocalModelService, settings: Settings,
                 events: EventStore | None = None) -> None:
        self.database, self.store, self.model, self.settings = database, store, model, settings
        self.events = events
        self.wakeup = asyncio.Event()

    async def _pieces(self, entries: list[Evidence], config: dict, *, empty_context: bool = False) -> AsyncIterator[PreparedChunk]:
        context = "" if empty_context else config.get("saved_context", "")[:512]
        prompt = SecurityPromptBuilder(model=config["model"], system_prompt=config["system_prompt"], saved_context=context, response_mode=self.model.response_mode)
        limit = config["context_tokens"] - OUTPUT_TOKENS - SAFETY_TOKENS
        while True:
            payload = prompt.build(entries)
            count = await self.model.count_input_tokens(payload)
            if count <= limit:
                yield PreparedChunk(entries, payload, count)
                return
            if not prompt.saved_context:
                break
            shortened = prompt.saved_context[:len(prompt.saved_context) // 2] if len(prompt.saved_context) > 128 else ""
            prompt = replace(prompt, saved_context=shortened)
        async for piece in Chunker(self.model, prompt, config["context_tokens"]).pack(iter(entries)):
            yield piece

    async def _save_plan(self, analysis_id: str, chunk_id: str, entries: list[Evidence], config: dict,
                         parent: dict | None = None) -> None:
        next_byte = entries[0].start_byte
        count = 0
        async for piece in self._pieces(entries, config, empty_context=parent is not None):
            for entry in piece.entries:
                if entry.start_byte != next_byte:
                    raise AppError(500, "inference_plan_invalid", "Inference evidence coverage is invalid.")
                next_byte = entry.end_byte
            count += 1
            position = f'{parent["position"]}.' if parent else ""
            position += f"{count:06d}"
            await run_in_threadpool(
                self.store.save_unit, analysis_id, chunk_id, position,
                [e.to_record() for e in piece.entries], piece.payload, piece.input_tokens,
                parent["id"] if parent else None,
            )
        if not count or next_byte != entries[-1].end_byte:
            raise AppError(500, "inference_plan_invalid", "Inference evidence coverage is incomplete.")

    async def _replan_unit(self, unit: dict, config: dict) -> None:
        if unit["position"].count(".") >= 3:
            raise AppError(422, "token_budget_exceeded", "The prompt cannot fit after bounded re-planning.")
        await run_in_threadpool(self.store.begin_split, unit["id"])
        try:
            await self._save_plan(unit["analysis_id"], unit["chunk_id"], evidence_from_records(unit["entries"]), config, unit)
        except BaseException:
            await run_in_threadpool(self.store.abort_split, unit["id"])
            raise
        await run_in_threadpool(self.store.finish_split, unit["id"])

    def _current_format(self, payload: dict) -> dict:
        payload = dict(payload)
        mode = self.model.response_mode
        if mode == "none":
            payload.pop("response_format", None)
        else:
            payload["response_format"] = SecurityPromptBuilder(response_mode=mode).build([])["response_format"]
        return payload

    async def _with_memory(self, unit: dict, entries: list[Evidence], config: dict) -> dict:
        payload = self._current_format(unit["payload"])
        if self.events is None:
            return payload
        memory = await run_in_threadpool(self.events.compact_context, unit["analysis_id"], entries)
        if not memory:
            return payload
        prompt = SecurityPromptBuilder(model=config["model"], system_prompt=config["system_prompt"],
                                       saved_context=memory, response_mode=self.model.response_mode)
        while True:
            payload = prompt.build(entries)
            count = await self.model.count_input_tokens(payload)
            if count + OUTPUT_TOKENS + SAFETY_TOKENS <= config["context_tokens"] or not prompt.saved_context:
                return payload  # generate() independently counts again immediately before POST.
            observations = json.loads(prompt.saved_context)["prior_observations"]
            shortened = json.dumps({"prior_observations": observations[:-1]}, separators=(",", ":")) if len(observations) > 1 else ""
            prompt = replace(prompt, saved_context=shortened)

    async def _execute(self, unit: dict, config: dict, source_path: Path) -> AppError | None:
        entries = evidence_from_records(unit["entries"])
        remaining = self.settings.inference_max_attempts - unit["round_attempts"]
        last_error: AppError = AppError(503, "retry_limit_reached", "The bounded retry limit was reached before checkpointing.")
        for attempt in range(max(0, remaining)):
            payload = await self._with_memory(unit, entries, config)
            attempt_id = await run_in_threadpool(self.store.begin_attempt, unit["id"], payload)
            started = perf_counter()
            diagnostics: dict = {"request_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}
            try:
                await run_in_threadpool(verify_original, source_path, entries)
                reply = await self.model.generate(payload, config["context_tokens"])
                diagnostics.update(reply.diagnostics)
                batch, recovery = parse_findings(reply.content)
                validate_evidence(batch, entries)
                diagnostics["json_recovery"] = recovery
                # Check again before accepting evidence if the source changed during generation.
                await run_in_threadpool(verify_original, source_path, entries)
            except asyncio.CancelledError:
                raise
            except (AppError, OSError) as exc:
                last_error = exc if isinstance(exc, AppError) else AppError(503, "storage_error", "The original uploaded log could not be read.")
                if isinstance(exc, ModelCallError):
                    diagnostics.update(exc.diagnostics)
                await run_in_threadpool(
                    self.store.finish_attempt, attempt_id, (perf_counter() - started) * 1000,
                    diagnostics, last_error.code, last_error.message, self.model.inference_uncertain,
                )
                if last_error.code == "token_budget_exceeded":
                    try:
                        await self._replan_unit(unit, config)
                        return None
                    except AppError as error:
                        last_error = error
                        break
                retryable = (
                    isinstance(exc, InvalidFindingResponse)
                    or isinstance(exc, ModelCallError) and exc.retryable
                    or last_error.code in {"tokenizer_unavailable", "tokenizer_timeout", "tokenizer_invalid_response"}
                )
                if not retryable or attempt + 1 == remaining:
                    break
                await asyncio.sleep(min(2.0, self.settings.inference_retry_backoff_seconds * 2 ** attempt))
                continue
            await run_in_threadpool(
                self.store.finish_attempt, attempt_id, (perf_counter() - started) * 1000,
                diagnostics, None, None, self.model.inference_uncertain,
            )
            await run_in_threadpool(self.store.complete_unit, unit, [f.model_dump() for f in batch.findings])
            return None
        await run_in_threadpool(self.store.fail_unit, unit["id"], last_error.code, last_error.message)
        return last_error if last_error.code in STOP_CODES else None

    async def process(self, run: dict) -> None:
        analysis_id, config = run["analysis_id"], run["config"]
        job = await run_in_threadpool(self.database.get_analysis, analysis_id)
        assert job is not None
        if self.events:
            await run_in_threadpool(self.events.ensure_indexed, analysis_id)
        source_path = Path(job["source_path"])
        while chunk_state := await run_in_threadpool(self.store.next_chunk, analysis_id):
            chunk_id = chunk_state["chunk_id"]
            try:
                if not chunk_state["planned"]:
                    await run_in_threadpool(self.store.clear_unfinished_plan, chunk_id)
                    chunk = await run_in_threadpool(self.database.get_chunk, analysis_id, chunk_id)
                    assert chunk is not None
                    entries = evidence_from_records(chunk["entries"])
                    await run_in_threadpool(verify_original, source_path, entries)
                    await self._save_plan(analysis_id, chunk_id, entries, config)
                    await run_in_threadpool(self.store.finish_plan, chunk_id)
                while unit := await run_in_threadpool(self.store.next_unit, chunk_id):
                    stop = await self._execute(unit, config, source_path)
                    if stop:
                        await run_in_threadpool(self.store.finish_chunk, chunk_id, stop.code, stop.message)
                        await run_in_threadpool(self.store.finish_run, analysis_id, stop.code, stop.message)
                        return
                await run_in_threadpool(self.store.finish_chunk, chunk_id)
                logger.info("inference_chunk_checkpoint analysis_id=%s chunk_id=%s", analysis_id, chunk_id)
            except (AppError, OSError) as exc:
                error = exc if isinstance(exc, AppError) else AppError(503, "storage_error", "The original uploaded log could not be read.")
                await run_in_threadpool(self.store.finish_chunk, chunk_id, error.code, error.message)
                if error.code in STOP_CODES:
                    await run_in_threadpool(self.store.finish_run, analysis_id, error.code, error.message)
                    return
        await run_in_threadpool(self.store.finish_run, analysis_id)

    async def run(self) -> None:
        while True:
            self.wakeup.clear()
            try:
                run = await run_in_threadpool(self.store.claim)
            except sqlite3.Error:
                logger.exception("inference_queue_unavailable")
                await asyncio.sleep(1)
                continue
            if run is None:
                await self.wakeup.wait()
                continue
            try:
                await self.process(run)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("inference_job_error analysis_id=%s error_type=%s", run["analysis_id"], type(exc).__name__)
                while True:
                    try:
                        await run_in_threadpool(self.store.finish_run, run["analysis_id"], "inference_job_error", "Inference stopped before the next checkpoint; completed findings are retained.")
                        break
                    except sqlite3.Error:
                        await asyncio.sleep(1)
