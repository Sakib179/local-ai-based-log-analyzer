from pathlib import Path

import pytest

from app.config import PROJECT_ROOT, Settings


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8080",
        "http://0.0.0.0:8080",
        "http://192.168.1.5:8080",
        "http://example.com:8080",
        "http://localhost.example.com:8080",
        "http://127.0.0.1.example.com:8080",
        "http://user:password@127.0.0.1:8080",
        "http://127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/?target=remote",
        "http://127.0.0.1:8080/#fragment",
        "http://127.0.0.1:8080?",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:invalid",
        "http://[::]:8080",
        "http://[::ffff:192.168.1.1]:8080",
        "http://[::1%lo0]:8080",
        " http://127.0.0.1:8080",
        "http://127.0.0.1:80\n80",
        "http://[invalid",
        "",
    ],
)
def test_remote_or_ambiguous_model_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="MODEL_BASE_URL"):
        Settings(model_base_url=url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost:8080/", "http://127.0.0.1:8080"),
        ("http://LOCALHOST:8080", "http://127.0.0.1:8080"),
        ("http://[::1]:8080/", "http://[::1]:8080"),
    ],
)
def test_loopback_urls_are_normalized(url: str, expected: str) -> None:
    assert Settings(model_base_url=url).model_base_url == expected


@pytest.mark.parametrize("timeout", [0.0, -1.0, 31.0, float("inf"), float("nan")])
def test_health_timeout_is_finite_and_bounded(timeout: float) -> None:
    with pytest.raises(ValueError, match="MODEL_HEALTH_TIMEOUT_SECONDS"):
        Settings(model_health_timeout_seconds=timeout)


@pytest.mark.parametrize("tokens", [0, -1, 2049])
def test_context_limit_cannot_exceed_evaluation_budget(tokens: int) -> None:
    with pytest.raises(ValueError, match="MODEL_CONTEXT_TOKENS"):
        Settings(model_context_tokens=tokens)


def test_environment_overrides_and_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("DATABASE_PATH", "data/custom.sqlite3")
    monkeypatch.setenv("MODEL_BASE_URL", "http://localhost:9090/")
    monkeypatch.setenv("MODEL_ALIAS", "local-test")
    monkeypatch.setenv("MODEL_HEALTH_TIMEOUT_SECONDS", "1.5")
    monkeypatch.setenv("MODEL_CONTEXT_TOKENS", "1024")
    monkeypatch.setenv("LOG_LEVEL", "warning")
    settings = Settings.from_env()
    assert settings.data_dir == tmp_path / "storage"
    assert settings.database_path == PROJECT_ROOT / "data/custom.sqlite3"
    assert settings.model_base_url == "http://127.0.0.1:9090"
    assert settings.model_alias == "local-test"
    assert settings.model_health_timeout_seconds == 1.5
    assert settings.model_context_tokens == 1024
    assert settings.log_level == "WARNING"


def test_database_defaults_to_configured_data_dir(tmp_path: Path) -> None:
    assert Settings(data_dir=tmp_path).database_path == tmp_path / "analyzer.sqlite3"


@pytest.mark.parametrize("overrides", [{"model_alias": " "}, {"log_level": "verbose"}])
def test_invalid_configuration_fails_early(overrides: dict) -> None:
    with pytest.raises(ValueError):
        Settings(**overrides)


@pytest.mark.parametrize("overrides", [
    {"max_upload_bytes": 0}, {"max_upload_bytes": -1},
    {"tokenizer_timeout_seconds": 0}, {"tokenizer_timeout_seconds": float("inf")},
])
def test_invalid_phase_two_limits_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValueError):
        Settings(**overrides)


@pytest.mark.parametrize("overrides", [
    {"inference_timeout_seconds": 0}, {"inference_timeout_seconds": float("nan")},
    {"inference_max_attempts": 0}, {"inference_max_attempts": 6},
    {"inference_retry_backoff_seconds": -1}, {"inference_retry_backoff_seconds": 3},
    {"inference_response_format": "arbitrary"},
])
def test_invalid_inference_configuration_is_rejected(overrides: dict) -> None:
    with pytest.raises(ValueError):
        Settings(**overrides)


@pytest.mark.parametrize("overrides", [
    {"auth_failure_threshold": 0}, {"auth_window_seconds": -1}, {"scan_path_threshold": 10001},
    {"request_rate_window_seconds": 0}, {"correlation_line_window": 0}, {"sql_repeat_threshold": 10001},
])
def test_correlation_limits_are_validated(overrides: dict) -> None:
    with pytest.raises(ValueError):
        Settings(**overrides)


def test_correlation_settings_can_be_overridden_by_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_FAILURE_THRESHOLD", "8")
    monkeypatch.setenv("AUTH_WINDOW_SECONDS", "900")
    monkeypatch.setenv("UNAUTHORIZED_WINDOW_SECONDS", "120")
    settings = Settings.from_env()
    assert settings.auth_failure_threshold == 8 and settings.auth_window_seconds == 900
    assert settings.unauthorized_window_seconds == 120
