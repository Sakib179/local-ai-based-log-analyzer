"""Streaming chunk packing verified against complete-chat tokenizer counts."""

from collections import deque
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from starlette.concurrency import run_in_threadpool

from app.errors import AppError
from app.services.parsing import Evidence, iter_evidence
from app.services.prompts import OUTPUT_TOKENS, SAFETY_TOKENS, PromptBuilder

BATCH_CHARS = 16384
BATCH_ENTRIES = 64


class TokenCounter(Protocol):
    async def count_input_tokens(self, payload: dict) -> int: ...


@dataclass(frozen=True, slots=True)
class PreparedChunk:
    entries: list[Evidence]
    payload: dict
    input_tokens: int


class Chunker:
    def __init__(self, tokenizer: TokenCounter, prompt: PromptBuilder, context_tokens: int = 2048) -> None:
        self.tokenizer = tokenizer
        self.prompt = prompt
        self.input_limit = context_tokens - OUTPUT_TOKENS - SAFETY_TOKENS

    async def _count(self, entries: list[Evidence]) -> PreparedChunk:
        payload = self.prompt.build(entries)
        count = await self.tokenizer.count_input_tokens(payload)
        if type(count) is not int or count < 0:
            raise AppError(503, "tokenizer_invalid_response", "The tokenizer returned an invalid count.")
        return PreparedChunk(entries, payload, count)

    async def chunks(self, path: Path) -> AsyncIterator[PreparedChunk]:
        async for chunk in self.pack(iter_evidence(path)):
            yield chunk

    async def pack(self, source: Iterator[Evidence]) -> AsyncIterator[PreparedChunk]:
        """Reuse exactly the same packer for bounded persisted evidence windows."""
        baseline = await self._count([])
        if baseline.input_tokens >= self.input_limit:
            raise AppError(422, "prompt_budget_exceeded", "The system prompt and context leave no log budget.")
        pending: deque[Evidence] = deque()
        exhausted = False
        try:
            while pending or not exhausted:
                chars = sum(len(e.raw) for e in pending)
                while not exhausted and len(pending) < BATCH_ENTRIES and chars < BATCH_CHARS:
                    entry = await run_in_threadpool(next, source, None)
                    if entry is None:
                        exhausted = True
                    else:
                        if pending and pending[-1].line_number == entry.line_number:
                            previous = pending.pop()
                            # Rejoin reader segments before tokenization when a whole
                            # entry fits the bounded window; do not split merely at I/O boundaries.
                            entry = Evidence(
                                previous.line_number, previous.start_char, previous.start_byte,
                                previous.raw + entry.raw,
                                previous.start_char > 0 or entry.continues, entry.continues,
                            )
                        pending.append(entry)
                        chars = sum(len(e.raw) for e in pending)
                if not pending:
                    break
                batch = list(pending)
                candidate = await self._count(batch)
                if candidate.input_tokens <= self.input_limit:
                    pending.clear()
                    yield candidate
                    continue

                # Search whole-entry prefixes, not individual words or estimated tokens.
                best: PreparedChunk | None = None
                low, high = 1, len(batch) - 1
                while low <= high:
                    middle = (low + high) // 2
                    counted = await self._count(batch[:middle])
                    if counted.input_tokens <= self.input_limit:
                        best, low = counted, middle + 1
                    else:
                        high = middle - 1
                if best is not None:
                    for _ in best.entries:
                        pending.popleft()
                    yield best
                    continue

                # The first entry cannot fit alone: find a verified character prefix.
                # Every emitted fragment carries its original line and precise offsets.
                entry = pending.popleft()
                low, high = 1, len(entry.raw)
                while low <= high:
                    middle = (low + high) // 2
                    counted = await self._count([entry.slice(0, middle)])
                    if counted.input_tokens <= self.input_limit:
                        best, low = counted, middle + 1
                    else:
                        high = middle - 1
                if best is None:
                    raise AppError(422, "prompt_budget_exceeded", "A log fragment cannot fit the prompt budget.")
                consumed = len(best.entries[0].raw)
                if consumed < len(entry.raw):
                    pending.appendleft(entry.slice(consumed, len(entry.raw)))
                yield best
        finally:
            close = getattr(source, "close", None)
            if close is not None:
                await run_in_threadpool(close)
