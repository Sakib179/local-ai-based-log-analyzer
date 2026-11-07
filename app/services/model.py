"""Shared local llama.cpp client, with serialized inference and bounded responses."""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass

import httpx

from app.config import CHAT_COMPLETIONS_PATH, INPUT_TOKENS_PATH, MODEL_HEALTH_PATH
from app.errors import AppError
from app.services.prompts import OUTPUT_TOKENS, SAFETY_TOKENS

logger = logging.getLogger("local_ai_security")
MAX_RESPONSE_BYTES = 65536


class ModelCallError(AppError):
    def __init__(self, code: str, message: str, *, retryable: bool = True, diagnostics: dict | None = None):
        super().__init__(503, code, message)
        self.retryable = retryable
        self.diagnostics = diagnostics or {}


@dataclass(frozen=True, slots=True)
class ModelReply:
    content: str
    input_tokens: int
    diagnostics: dict


class LocalModelService:
    def __init__(
        self, client: httpx.AsyncClient, health_timeout_seconds: float,
        tokenizer_timeout_seconds: float = 30.0,
        inference_timeout_seconds: float = 120.0,
        response_format: str = "auto",
    ) -> None:
        self.client = client
        self.health_timeout_seconds = health_timeout_seconds
        self.tokenizer_timeout_seconds = tokenizer_timeout_seconds
        self.tokenizer_lock = asyncio.Lock()
        self.inference_lock = asyncio.Lock()
        self.inference_timeout_seconds = inference_timeout_seconds
        self.response_mode = "schema" if response_format == "auto" else response_format
        self.inference_uncertain = False

    async def _bounded_request(self, method: str, path: str, timeout: float, payload: dict | None = None) -> tuple[int, bytes]:
        raw = bytearray()
        async with self.client.stream(method, path, json=payload, timeout=timeout) as response:
            async for piece in response.aiter_bytes():
                if len(raw) + len(piece) > MAX_RESPONSE_BYTES:
                    raise ModelCallError("model_response_too_large", "The model response exceeded its size limit.", retryable=False)
                raw.extend(piece)
            return response.status_code, bytes(raw)

    async def _ensure_idle_after_uncertain_call(self) -> None:
        if not self.inference_uncertain:
            return
        try:
            async with asyncio.timeout(5):
                while True:
                    status, raw = await self._bounded_request("GET", "/slots", 3)
                    slots = json.loads(raw) if status == 200 else None
                    if not isinstance(slots, list) or not slots or any(
                        not isinstance(slot, dict) or type(slot.get("is_processing")) is not bool for slot in slots
                    ):
                        break
                    if all(not slot["is_processing"] for slot in slots):
                        self.inference_uncertain = False
                        return
                    await asyncio.sleep(0.2)
        except (TimeoutError, httpx.HTTPError, ValueError, ModelCallError):
            pass
        raise ModelCallError(
            "model_state_uncertain",
            "A previous inference may still be running. Cannot verify idle llama.cpp slots; retry after checking the local server.",
            retryable=False,
        )

    async def generate(self, payload: dict, context_tokens: int = 2048) -> ModelReply:
        """Exactly one application inference at a time, counting immediately before POST."""
        async with self.inference_lock:
            await self._ensure_idle_after_uncertain_call()
            # These required generation settings cannot be overridden by a saved payload.
            payload = {**payload, "max_tokens": OUTPUT_TOKENS, "temperature": 0.1, "stream": False}
            input_tokens = await self.count_input_tokens(payload)
            if input_tokens + OUTPUT_TOKENS + SAFETY_TOKENS > min(context_tokens, 2048):
                raise ModelCallError(
                    "token_budget_exceeded", "The complete inference prompt exceeds the reserved token budget.",
                    retryable=False, diagnostics={"input_tokens": input_tokens},
                )
            self.inference_uncertain = True
            try:
                async with asyncio.timeout(self.inference_timeout_seconds):
                    status, raw = await self._bounded_request(
                        "POST", CHAT_COMPLETIONS_PATH, self.inference_timeout_seconds, payload
                    )
            except (httpx.ConnectError, httpx.ConnectTimeout):
                self.inference_uncertain = False
                raise ModelCallError("model_unavailable", "Cannot connect to the local llama.cpp server.", diagnostics={"input_tokens": input_tokens}) from None
            except (TimeoutError, httpx.TimeoutException):
                raise ModelCallError("model_timeout", "Local inference timed out; an idle-slot check is required before retry.", diagnostics={"input_tokens": input_tokens}) from None
            except httpx.HTTPError:
                raise ModelCallError("model_connection_error", "The local model connection failed during inference.", diagnostics={"input_tokens": input_tokens}) from None
            except ModelCallError as error:
                error.diagnostics.setdefault("input_tokens", input_tokens)
                raise
            self.inference_uncertain = False
            diagnostics = {
                "response_sha256": hashlib.sha256(raw).hexdigest(), "response_bytes": len(raw),
                "http_status": status, "input_tokens": input_tokens,
            }
            if status in {400, 422} and "response_format" in payload and any(
                word in raw.lower() for word in (b"response_format", b"schema", b"grammar")
            ):
                self.response_mode = "json_object" if self.response_mode == "schema" else "none"
                raise ModelCallError("response_format_unsupported", "The server rejected structured output; retrying a simpler JSON format.", diagnostics=diagnostics)
            if status != 200:
                raise ModelCallError(
                    "model_server_error" if status >= 500 else "model_request_error",
                    "The local model server rejected the inference request.",
                    retryable=status in {429, 500, 502, 503, 504}, diagnostics=diagnostics,
                )
            try:
                body = json.loads(raw)
                choice = body["choices"][0]
                content = choice["message"]["content"]
                finish_reason = choice.get("finish_reason")
                if not isinstance(content, str) or not content.strip():
                    raise ValueError
            except (ValueError, KeyError, IndexError, TypeError, RecursionError):
                raise ModelCallError("model_invalid_response", "The local model returned missing, empty, or invalid response fields.", diagnostics=diagnostics) from None
            if finish_reason == "length":
                raise ModelCallError("truncated_model_response", "The local model output reached its token limit.", diagnostics=diagnostics)
            return ModelReply(content, input_tokens, diagnostics)

    async def count_input_tokens(self, payload: dict) -> int:
        """Count the exact complete chat payload, including the server's template."""
        try:
            async with asyncio.timeout(self.tokenizer_timeout_seconds):
                async with self.tokenizer_lock:
                    response = await self.client.post(
                        INPUT_TOKENS_PATH, json=payload, timeout=self.tokenizer_timeout_seconds
                    )
        except (TimeoutError, httpx.TimeoutException):
            raise AppError(503, "tokenizer_timeout", "The local tokenizer timed out.") from None
        except httpx.HTTPError:
            raise AppError(503, "tokenizer_unavailable", "Cannot reach the local tokenizer.") from None
        if response.status_code != 200:
            raise AppError(
                503, "tokenizer_unavailable",
                "The local tokenizer endpoint is unavailable; check llama.cpp and its version.",
            )
        try:
            body = response.json()
        except ValueError:
            body = None
        tokens = body.get("input_tokens") if isinstance(body, dict) else None
        if type(tokens) is not int or tokens < 0:
            raise AppError(503, "tokenizer_invalid_response", "The tokenizer returned an invalid count.")
        return tokens

    async def check_health(self) -> None:
        try:
            # Bound total elapsed time, including the connection pool wait and body read.
            async with asyncio.timeout(self.health_timeout_seconds):
                response = await self.client.get(MODEL_HEALTH_PATH)
        except (TimeoutError, httpx.TimeoutException):
            raise AppError(503, "model_timeout", "The local model health check timed out.") from None
        except httpx.HTTPError as exc:
            logger.warning("model_connection_failed error_type=%s", type(exc).__name__)
            raise AppError(
                503, "model_unavailable", "Cannot reach llama.cpp. Start the local model server."
            ) from None

        if response.status_code != 200:
            raise AppError(
                503, "model_not_ready", "The local model server is not ready. It may still be loading."
            )
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or body.get("status") != "ok":
            raise AppError(
                503, "model_invalid_response", "The local model server returned an invalid health response."
            )
