import asyncio
import sqlite3
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def unreachable_model(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("Connection refused", request=request)


def test_backend_and_page_work_without_model(settings: Settings) -> None:
    app = create_app(settings, model_transport=httpx.MockTransport(unreachable_model))
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "database": "ok", "version": "0.1.0"}
        assert len(response.headers["X-Request-ID"]) == 32
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        page = client.get("/")
        assert page.status_code == 200
        assert "text/html" in page.headers["content-type"]
        assert "Local AI Security Log Analyzer" in page.text
        assert "Local dashboard" in page.text
        assert "Phase 5" not in page.text
        assert "http://127.0.0.1:8080" in page.text
        assert client.get("/static/styles.css").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        model = client.get("/api/model/health")
        assert model.status_code == 503
        assert model.json()["error"]["code"] == "model_unavailable"
        assert client.get("/health").status_code == 200
    assert settings.database_path is not None and settings.database_path.is_file()
    assert app.state.model_service.client.is_closed


def test_model_health_uses_real_health_contract_and_local_target(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Proxy configuration must never redirect local model traffic to another service.
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid:9999")
    monkeypatch.setenv("ALL_PROXY", "http://untrusted.invalid:9999")
    monkeypatch.setenv("NO_PROXY", "")
    requests: list[httpx.Request] = []

    def healthy_model(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"status": "ok"})

    app = create_app(settings, model_transport=httpx.MockTransport(healthy_model))
    with TestClient(app) as client:
        response = client.get("/api/model/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "model": "qwen-local"}
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert str(requests[0].url) == "http://127.0.0.1:8080/health"
    assert requests[0].content == b""


@pytest.mark.parametrize(
    ("upstream", "code"),
    [
        (httpx.Response(503, json={"error": {"message": "Loading model"}}), "model_not_ready"),
        (httpx.Response(500, text="private upstream error"), "model_not_ready"),
        (httpx.Response(200, text="not JSON"), "model_invalid_response"),
        (httpx.Response(200, json={"status": "loading"}), "model_invalid_response"),
        (httpx.Response(200, json=["ok"]), "model_invalid_response"),
    ],
)
def test_unready_and_invalid_model_responses(
    settings: Settings, upstream: httpx.Response, code: str
) -> None:
    app = create_app(settings, model_transport=httpx.MockTransport(lambda _request: upstream))
    with TestClient(app) as client:
        response = client.get("/api/model/health")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == code
        assert "private upstream error" not in response.text


def test_model_redirect_is_not_followed(settings: Settings) -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "http://external.invalid/health"})

    app = create_app(settings, model_transport=httpx.MockTransport(redirect))
    with TestClient(app) as client:
        assert client.get("/api/model/health").status_code == 503
    assert len(requests) == 1


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout])
def test_model_http_timeouts(settings: Settings, failure: type[httpx.TimeoutException]) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise failure("private timeout details", request=request)

    app = create_app(settings, model_transport=httpx.MockTransport(timeout))
    with TestClient(app) as client:
        response = client.get("/api/model/health")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "model_timeout"
        assert "private timeout details" not in response.text


def test_total_model_deadline(settings: Settings) -> None:
    async def slow_model(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(200, json={"status": "ok"})

    app = create_app(
        replace(settings, model_health_timeout_seconds=0.01),
        model_transport=httpx.MockTransport(slow_model),
    )
    with TestClient(app) as client:
        response = client.get("/api/model/health")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "model_timeout"


def test_framework_and_unexpected_errors_have_same_envelope(settings: Settings) -> None:
    app = create_app(settings)

    @app.get("/test/exception", include_in_schema=False)
    async def exception_route() -> None:
        raise RuntimeError("private exception details")

    @app.get("/test/validation", include_in_schema=False)
    async def validation_route(count: int) -> dict[str, int]:
        return {"count": count}

    with TestClient(app) as client:
        for url, status, code in [
            ("/missing", 404, "http_404"),
            ("/static/missing.css", 404, "http_404"),
            ("/test/exception", 500, "internal_error"),
            ("/test/validation?count=private-invalid-input", 422, "validation_error"),
        ]:
            response = client.get(url)
            assert response.status_code == status
            assert set(response.json()) == {"error"}
            assert set(response.json()["error"]) == {"code", "message"}
            assert response.json()["error"]["code"] == code
            assert "private" not in response.text
            assert "X-Request-ID" in response.headers
        response = client.post("/health")
        assert response.status_code == 405
        assert response.headers["Allow"] == "GET"


def test_database_failure_returns_503_without_private_details(settings: Settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.connection() as connection:
            connection.execute("DROP TABLE app_metadata")
        response = client.get("/health")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "database_unavailable"
        assert "app_metadata" not in response.text


def test_unsupported_database_version_is_not_reported_healthy(settings: Settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.connection() as connection:
            connection.execute("UPDATE app_metadata SET value = '99' WHERE key = 'schema_version'")
        assert client.get("/health").status_code == 503


def test_database_initialization_failure_prevents_startup(settings: Settings) -> None:
    settings.data_dir.mkdir(parents=True)
    assert settings.database_path is not None
    settings.database_path.write_text("invalid SQLite file")
    with pytest.raises(sqlite3.DatabaseError):
        with TestClient(create_app(settings)):
            pytest.fail("Application should not have started with an invalid database.")


def test_template_escapes_configuration_values(settings: Settings) -> None:
    app = create_app(replace(settings, model_alias="<script>alert('test')</script>"))
    with TestClient(app) as client:
        response = client.get("/")
        assert "<script>alert" not in response.text
        assert "&lt;script&gt;" in response.text


def test_no_cdn_docs_or_later_phase_routes(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        paths = client.get("/openapi.json").json()["paths"]
        assert set(paths) == {
            "/health", "/api/model/health", "/api/analyses", "/api/analyses/{analysis_id}",
            "/api/analyses/{analysis_id}/chunks", "/api/analyses/{analysis_id}/chunks/{chunk_id}",
            "/api/analyses/{analysis_id}/start", "/api/analyses/{analysis_id}/findings",
            "/api/analyses/{analysis_id}/attempts",
            "/api/analyses/{analysis_id}/report",
        }
