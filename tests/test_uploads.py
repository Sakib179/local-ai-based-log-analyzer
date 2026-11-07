import asyncio
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import INPUT_TOKENS_PATH, Settings
from app.database import Database
from app.main import create_app
from app.services.uploads import UploadReceiver
from test_chunking import FakeTokenizer


class FakeModel:
    def __init__(self):
        self.payloads: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        assert request.method == "POST" and request.url.path == INPUT_TOKENS_PATH
        payload = json.loads(request.content)
        self.payloads.append(payload)
        return httpx.Response(200, json={"input_tokens": FakeTokenizer.count(payload)})


def wait_for_job(client: TestClient, analysis_id: str, timeout: float = 8) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/analyses/{analysis_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"ready", "failed"}:
            return job
        time.sleep(0.01)
    pytest.fail("Job preparation did not finish")


@pytest.mark.parametrize("extension", ["log", "txt", "LOG"])
def test_valid_upload_and_inspection(settings: Settings, extension: str) -> None:
    fake = FakeModel()
    raw = b'192.0.2.1 - alice [07/Nov/2026:12:00:00 +0600] "GET /private HTTP/1.1" 403 12\r\n\nlast'
    app = create_app(settings, model_transport=httpx.MockTransport(fake))
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"file": (f"server.{extension}", raw, "text/plain")})
        assert response.status_code == 202
        analysis_id = response.json()["id"]
        assert UUID(analysis_id).version == 4
        assert response.json()["status"] == "queued"
        job = wait_for_job(client, analysis_id)
        assert job["status"] == "ready"
        assert job["size_bytes"] == len(raw)
        assert job["total_lines"] == 3
        assert job["total_chunks"] >= 1
        assert job["sha256"] == hashlib.sha256(raw).hexdigest()
        assert job["filename"] == f"server.{extension}"
        assert "source_path" not in job and "preparation_config" not in job
        chunks = client.get(f"/api/analyses/{analysis_id}/chunks").json()
        assert chunks["total"] == job["total_chunks"]
        assert chunks["chunks"][0]["start_line"] == 1
        restored = []
        for chunk in chunks["chunks"]:
            assert chunk["input_tokens"] + 384 + 64 <= 2048
            detail = client.get(f'/api/analyses/{analysis_id}/chunks/{chunk["id"]}').json()
            assert detail["payload"] in fake.payloads
            assert detail["entries"][0]["fields"]["status"] == 403
            restored.extend(e["raw"] for e in detail["entries"])
        assert "".join(restored).encode() == raw
        assert (settings.data_dir / "uploads" / f"{analysis_id}.log").read_bytes() == raw


@pytest.mark.parametrize(
    ("name", "content", "mime", "status", "code"),
    [
        ("file.csv", b"hello", "text/plain", 415, "unsupported_file_type"),
        ("file.log.exe", b"hello", "text/plain", 415, "unsupported_file_type"),
        ("file.log", b"", "text/plain", 400, "empty_file"),
        ("file.log", b" \r\n\t", "text/plain", 400, "empty_file"),
        ("file.txt", b"abc\x00def", "text/plain", 415, "binary_file"),
        ("file.log", b"abc\xffdef", "text/plain", 415, "binary_file"),
        ("file.log", b"abc\xc3", "text/plain", 415, "binary_file"),
        ("file.log", b"\x89PNG\r\n\x1a\n", "application/octet-stream", 415, "binary_file"),
        ("file.log", b"hello", "image/png", 415, "unsupported_file_type"),
        ("file.log", b"a" * 129, "text/plain", 413, "file_too_large"),
    ],
)
def test_invalid_uploads_are_rejected_and_partial_files_removed(
    settings: Settings, name: str, content: bytes, mime: str, status: int, code: str
) -> None:
    fake = FakeModel()
    app = create_app(replace(settings, max_upload_bytes=128), model_transport=httpx.MockTransport(fake))
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"file": (name, content, mime)})
        assert response.status_code == status, response.text
        assert response.json()["error"]["code"] == code
        assert not list((settings.data_dir / "uploads").iterdir())
        assert fake.payloads == []


def test_exact_size_limit_and_untrusted_filenames(settings: Settings) -> None:
    app = create_app(replace(settings, max_upload_bytes=128), model_transport=httpx.MockTransport(FakeModel()))
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"file": ("../../escape.log", b"a" * 128)})
        assert response.status_code == 202
        job = wait_for_job(client, response.json()["id"])
        assert job["status"] == "ready"
        assert job["filename"] == "escape.log"
        assert not (settings.data_dir.parent / "escape.log").exists()
        assert [p.name for p in (settings.data_dir / "uploads").iterdir()] == [f'{job["id"]}.log']


def test_chunked_request_without_content_length_and_split_utf8(settings: Settings) -> None:
    raw = "用户 failed login\r\n".encode()
    body = (b'--abc\r\nContent-Disposition: form-data; name="file"; filename="log.txt"\r\n'
            b'Content-Type: text/plain\r\n\r\n' + raw + b'\r\n--abc--\r\n')
    app = create_app(settings, model_transport=httpx.MockTransport(FakeModel()))
    with TestClient(app) as client:
        response = client.post("/api/analyses", headers={"content-type": "multipart/form-data; boundary=abc"},
                               content=(body[i:i + 1] for i in range(len(body))))
        assert response.status_code == 202, response.text
        assert wait_for_job(client, response.json()["id"])["status"] == "ready"


def test_streaming_parser_handles_utf8_and_headers_split_between_bytes(tmp_path: Path) -> None:
    raw = "用户 failed login\r\n".encode()
    body = (b'--abc\r\nContent-Disposition: form-data; name="file"; filename="a.log"\r\n\r\n'
            + raw + b'\r\n--abc--\r\n')
    target = tmp_path / "stream.part"
    receiver = UploadReceiver(target, 1024, b"abc")
    try:
        for byte in body:
            receiver.feed(bytes([byte]))
        receiver.finish()
    finally:
        receiver.file.close()
    assert target.read_bytes() == raw
    assert receiver.size == len(raw)


def test_actual_file_bytes_override_missing_or_false_content_length(settings: Settings) -> None:
    body = (b'--abc\r\nContent-Disposition: form-data; name="file"; filename="a.log"\r\n\r\n'
            + b"x" * 129 + b'\r\n--abc--\r\n')
    with TestClient(create_app(replace(settings, max_upload_bytes=128))) as client:
        response = client.post(
            "/api/analyses", content=(body[i:i + 7] for i in range(0, len(body), 7)),
            headers={"content-type": "multipart/form-data; boundary=abc", "content-length": "1"},
        )
        assert response.status_code == 413
        assert not list((settings.data_dir / "uploads").iterdir())


@pytest.mark.parametrize("body", [b"", b"--abc\r\n", b'--abc\r\nContent-Disposition: form-data; name="file"; filename="a.log"\r\n\r\nhello'])
def test_truncated_or_missing_multipart_is_rejected(settings: Settings, body: bytes) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/analyses", headers={"content-type": "multipart/form-data; boundary=abc"}, content=body)
        assert response.status_code == 400
        assert not list((settings.data_dir / "uploads").iterdir())


def test_multiple_files_and_non_file_fields_are_rejected(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/analyses", files=[("file", ("a.log", b"hello")), ("file", ("b.log", b"hello"))])
        assert response.status_code == 400
        response = client.post("/api/analyses", files={"wrong": ("a.log", b"hello")})
        assert response.status_code == 400
        assert not list((settings.data_dir / "uploads").iterdir())


@pytest.mark.parametrize("tokenizer_response", [httpx.Response(404), httpx.Response(200, json={"input_tokens": True}), httpx.Response(200, text="invalid")])
def test_tokenizer_failure_is_persisted_without_fallback(settings: Settings, tokenizer_response: httpx.Response) -> None:
    app = create_app(settings, model_transport=httpx.MockTransport(lambda _request: tokenizer_response))
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"file": ("a.log", b"login failed\n")})
        assert response.status_code == 202
        job = wait_for_job(client, response.json()["id"])
        assert job["status"] == "failed"
        assert job["error"]["code"].startswith("tokenizer_")
        assert job["total_chunks"] == 0
        assert (settings.data_dir / "uploads" / f'{job["id"]}.log').exists()


def test_interrupted_preparation_is_recovered_on_restart(settings: Settings) -> None:
    async def blocked_tokenizer(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        return httpx.Response(200, json={"input_tokens": 100})

    with TestClient(create_app(settings, model_transport=httpx.MockTransport(blocked_tokenizer))) as client:
        response = client.post("/api/analyses", files={"file": ("a.log", b"hello\nworld\n")})
        analysis_id = response.json()["id"]
        for _ in range(100):
            if client.get(f"/api/analyses/{analysis_id}").json()["status"] == "processing":
                break
            time.sleep(0.01)
        else:
            pytest.fail("Worker did not claim the job")
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(FakeModel()))) as client:
        job = wait_for_job(client, analysis_id)
        assert job["status"] == "ready"
        assert job["total_chunks"] == 1
        assert job["total_lines"] == 2


def test_pagination_and_job_boundaries(settings: Settings) -> None:
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(FakeModel()))) as client:
        response = client.post("/api/analyses", files={"file": ("a.log", b"entry\n" * 500)})
        analysis_id = response.json()["id"]
        job = wait_for_job(client, analysis_id)
        assert job["status"] == "ready" and job["total_chunks"] > 1
        first = client.get(f"/api/analyses/{analysis_id}/chunks?limit=1").json()
        second = client.get(f"/api/analyses/{analysis_id}/chunks?limit=1&offset=1").json()
        assert first["chunks"][0]["ordinal"] == 1
        assert second["chunks"][0]["ordinal"] == 2
        assert "entries" not in first["chunks"][0]
        assert client.get(f"/api/analyses/{analysis_id}/chunks?limit=101").status_code == 422
        assert client.get(f"/api/analyses/{uuid4()}").status_code == 404
        assert client.get(f"/api/analyses/{analysis_id}/chunks/{uuid4()}").status_code == 404
