"""Validated environment configuration using only the standard library."""

import ipaddress
import math
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "Local AI Security Log Analyzer"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
INPUT_TOKENS_PATH = "/v1/chat/completions/input_tokens"
MODEL_HEALTH_PATH = "/health"


def _project_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def _loopback_url(value: str) -> str:
    """Avoid remote hosts, DNS lookups, credentials, redirects, and URL prefixes."""
    try:
        if any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme != "http"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
        ):
            raise ValueError
        host = "127.0.0.1" if host == "localhost" else host
        address = ipaddress.ip_address(host)
        if not address.is_loopback or "%" in host:
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        authority = f"[{address}]" if address.version == 6 else str(address)
        return f"http://{authority}" + (f":{port}" if port is not None else "")
    except ValueError:
        raise ValueError(
            "MODEL_BASE_URL must be an HTTP loopback URL with no credentials, "
            "path prefix, query, or fragment (for example http://127.0.0.1:8080)."
        ) from None


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path = PROJECT_ROOT / "data"
    database_path: Path | None = None
    log_level: str = "INFO"
    model_base_url: str = "http://127.0.0.1:8080"
    model_alias: str = "qwen-local"
    model_health_timeout_seconds: float = 3.0
    model_context_tokens: int = 2048
    max_upload_bytes: int = 10 * 1024 * 1024
    tokenizer_timeout_seconds: float = 30.0
    inference_timeout_seconds: float = 120.0
    inference_max_attempts: int = 3
    inference_retry_backoff_seconds: float = 0.25
    inference_response_format: str = "auto"
    auth_failure_threshold: int = 5
    auth_window_seconds: int = 1800
    correlation_line_window: int = 10000
    sql_repeat_threshold: int = 2
    sql_window_seconds: int = 600
    scan_path_threshold: int = 5
    scan_window_seconds: int = 300
    unauthorized_threshold: int = 5
    unauthorized_window_seconds: int = 300
    request_rate_threshold: int = 100
    request_rate_window_seconds: int = 60

    def __post_init__(self) -> None:
        data_dir = _project_path(self.data_dir)
        database_path = (
            _project_path(self.database_path)
            if self.database_path is not None
            else data_dir / "analyzer.sqlite3"
        )
        log_level = self.log_level.upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL.")
        if not self.model_alias.strip():
            raise ValueError("MODEL_ALIAS must not be empty.")
        if not math.isfinite(self.model_health_timeout_seconds) or not (
            0 < self.model_health_timeout_seconds <= 30
        ):
            raise ValueError("MODEL_HEALTH_TIMEOUT_SECONDS must be greater than 0 and at most 30.")
        if not 1 <= self.model_context_tokens <= 2048:
            raise ValueError("MODEL_CONTEXT_TOKENS must be between 1 and 2048.")
        if self.max_upload_bytes < 1:
            raise ValueError("MAX_UPLOAD_BYTES must be positive.")
        if not math.isfinite(self.tokenizer_timeout_seconds) or not (
            0 < self.tokenizer_timeout_seconds <= 120
        ):
            raise ValueError("TOKENIZER_TIMEOUT_SECONDS must be greater than 0 and at most 120.")
        if not math.isfinite(self.inference_timeout_seconds) or not 0 < self.inference_timeout_seconds <= 600:
            raise ValueError("INFERENCE_TIMEOUT_SECONDS must be greater than 0 and at most 600.")
        if not 1 <= self.inference_max_attempts <= 5:
            raise ValueError("INFERENCE_MAX_ATTEMPTS must be between 1 and 5.")
        if not math.isfinite(self.inference_retry_backoff_seconds) or not 0 <= self.inference_retry_backoff_seconds <= 2:
            raise ValueError("INFERENCE_RETRY_BACKOFF_SECONDS must be between 0 and 2.")
        if self.inference_response_format not in {"auto", "json_object", "none"}:
            raise ValueError("INFERENCE_RESPONSE_FORMAT must be auto, json_object, or none.")
        for name in (
            "auth_failure_threshold", "auth_window_seconds", "correlation_line_window",
            "sql_repeat_threshold", "sql_window_seconds", "scan_path_threshold", "scan_window_seconds",
            "unauthorized_threshold", "request_rate_threshold", "request_rate_window_seconds",
            "unauthorized_window_seconds",
        ):
            if not 1 <= getattr(self, name) <= 1_000_000:
                raise ValueError(f"{name.upper()} must be between 1 and 1000000.")
            if name.endswith("threshold") and getattr(self, name) > 10000:
                raise ValueError(f"{name.upper()} must not exceed 10000 (bounded correlation memory).")
        object.__setattr__(self, "data_dir", data_dir)
        object.__setattr__(self, "database_path", database_path)
        object.__setattr__(self, "log_level", log_level)
        object.__setattr__(self, "model_base_url", _loopback_url(self.model_base_url))

    @classmethod
    def from_env(cls) -> "Settings":
        """Read the process environment; uv can optionally load a .env file."""
        database_path = os.environ.get("DATABASE_PATH")
        return cls(
            data_dir=Path(os.environ.get("DATA_DIR", "data")),
            database_path=Path(database_path) if database_path else None,
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            model_base_url=os.environ.get("MODEL_BASE_URL", "http://127.0.0.1:8080"),
            model_alias=os.environ.get("MODEL_ALIAS", "qwen-local"),
            model_health_timeout_seconds=float(
                os.environ.get("MODEL_HEALTH_TIMEOUT_SECONDS", "3")
            ),
            model_context_tokens=int(os.environ.get("MODEL_CONTEXT_TOKENS", "2048")),
            max_upload_bytes=int(os.environ.get("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024))),
            tokenizer_timeout_seconds=float(os.environ.get("TOKENIZER_TIMEOUT_SECONDS", "30")),
            inference_timeout_seconds=float(os.environ.get("INFERENCE_TIMEOUT_SECONDS", "120")),
            inference_max_attempts=int(os.environ.get("INFERENCE_MAX_ATTEMPTS", "3")),
            inference_retry_backoff_seconds=float(os.environ.get("INFERENCE_RETRY_BACKOFF_SECONDS", "0.25")),
            inference_response_format=os.environ.get("INFERENCE_RESPONSE_FORMAT", "auto"),
            **{name: int(os.environ.get(name.upper(), str(default))) for name, default in {
                "auth_failure_threshold": 5, "auth_window_seconds": 1800, "correlation_line_window": 10000,
                "sql_repeat_threshold": 2, "sql_window_seconds": 600, "scan_path_threshold": 5,
                "scan_window_seconds": 300, "unauthorized_threshold": 5,
                "unauthorized_window_seconds": 300,
                "request_rate_threshold": 100, "request_rate_window_seconds": 60,
            }.items()},
        )
