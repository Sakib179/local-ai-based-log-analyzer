"""A single durable SQLite-backed preparation worker; no AI generation."""

import asyncio
import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from uuid import UUID, uuid4

from starlette.concurrency import run_in_threadpool

from app.database import Database
from app.errors import AppError
from app.services.chunking import Chunker, TokenCounter
from app.services.prompts import PromptBuilder

logger = logging.getLogger("local_ai_security")


class PreparationWorker:
    def __init__(self, database: Database, tokenizer: TokenCounter, uploads_dir: Path) -> None:
        self.database = database
        self.tokenizer = tokenizer
        self.uploads_dir = uploads_dir
        self.wakeup = asyncio.Event()

    def recover(self) -> None:
        self.database.recover_interrupted()
        # Only server-generated UUID paths are eligible for cleanup.
        for path in self.uploads_dir.iterdir():
            try:
                UUID(path.stem)
            except ValueError:
                continue
            if path.suffix == ".part":
                path.unlink(missing_ok=True)
            elif path.suffix == ".log":
                job = self.database.get_analysis(path.stem)
                if job is None or job["error_code"] == "upload_interrupted":
                    path.unlink(missing_ok=True)

    async def prepare(self, job: dict) -> None:
        config = json.loads(job["preparation_config"])
        chunker = Chunker(self.tokenizer, PromptBuilder(**config["prompt"]), config["context_tokens"])
        ordinal = 0
        next_byte = 0
        digest = hashlib.sha256()
        async for chunk in chunker.chunks(Path(job["source_path"])):
            for entry in chunk.entries:
                if entry.start_byte != next_byte:
                    raise RuntimeError("Evidence byte coverage is not contiguous.")
                next_byte = entry.end_byte
                digest.update(entry.raw.encode("utf-8"))
            ordinal += 1
            await run_in_threadpool(
                self.database.save_chunk, job["id"], str(uuid4()), ordinal,
                [entry.to_record() for entry in chunk.entries], chunk.payload, chunk.input_tokens,
            )
        if next_byte != job["size_bytes"] or ordinal == 0 or digest.hexdigest() != job["sha256"]:
            raise RuntimeError("Prepared evidence does not match the uploaded file size.")
        await run_in_threadpool(self.database.finish_analysis, job["id"])
        logger.info("preparation_ready analysis_id=%s chunks=%s", job["id"], ordinal)

    async def run(self) -> None:
        while True:
            self.wakeup.clear()
            try:
                job = await run_in_threadpool(self.database.claim_analysis)
            except Exception:
                logger.exception("preparation_queue_error")
                await asyncio.sleep(1)
                continue
            if job is None:
                await self.wakeup.wait()
                continue
            try:
                await self.prepare(job)
            except asyncio.CancelledError:
                # Retain 'processing' and the original file for recovery at next startup.
                raise
            except Exception as exc:
                if isinstance(exc, AppError):
                    code, message = exc.code, exc.message
                elif isinstance(exc, OSError):
                    code, message = "storage_error", "The uploaded log could not be read or stored."
                else:
                    code, message = "preparation_failed", "Log preparation failed."
                logger.error("preparation_failed analysis_id=%s code=%s", job["id"], code)
                while True:
                    try:
                        await run_in_threadpool(self.database.fail_analysis, job["id"], code, message)
                        break
                    except (sqlite3.Error, OSError):
                        # Keep the current job until its failure can be durably recorded.
                        logger.exception("preparation_failure_persistence_error analysis_id=%s", job["id"])
                        await asyncio.sleep(1)
