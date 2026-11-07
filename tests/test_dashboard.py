"""Dashboard integration contracts; no JavaScript runtime or model required."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from threading import Event
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.database import Database
from app.inference_database import InferenceStore
from app.main import create_app
from test_inference import InferenceModel, upload_ready, wait_inference
from test_correlation import seed_prepared


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.elements.append((tag, dict(attrs)))


def test_dashboard_has_working_local_assets_and_configured_upload_limit(settings: Settings) -> None:
    with TestClient(create_app(replace(settings, max_upload_bytes=123456))) as client:
        response = client.get("/")
        page = PageParser()
        page.feed(response.text)
        ids = {attrs["id"] for _, attrs in page.elements if "id" in attrs}
        assert {"log-file", "dropzone", "upload-button", "start-analysis", "analysis-progress", "refresh-status",
                "filter-search", "filter-severity", "filter-type", "filter-multiple", "download-report", "findings-list"} <= ids
        assert next(attrs for tag, attrs in page.elements if tag == "body")["data-max-upload-bytes"] == "123456"
        for tag, attrs in page.elements:
            if tag == "script" or tag == "link" and attrs.get("rel") == "stylesheet":
                url = attrs.get("src", attrs.get("href"))
                assert url.startswith("http://testserver/static/")
                assert client.get(url).status_code == 200
        assert "Enable JavaScript" in response.text
        script = client.get("/static/app.js").text
        assert "innerHTML" not in script and "insertAdjacentHTML" not in script and "eval(" not in script
        assert "textContent" in script


def test_report_download_exports_the_actual_combined_report(settings: Settings) -> None:
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(InferenceModel(["{\"findings\":[]}"])))) as client:
        analysis_id = upload_ready(client)
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        report = client.get(f"/api/analyses/{analysis_id}/report").json()
        download = client.get(f"/api/analyses/{analysis_id}/report?download=true")
        assert download.status_code == 200
        assert download.json() == report
        assert download.headers["content-disposition"] == f'attachment; filename="security-report-{analysis_id}.json"'
        assert download.headers["content-type"] == "application/json"
        assert "content-disposition" not in client.get(f"/api/analyses/{analysis_id}/report").headers
        assert client.get(f"/api/analyses/{uuid4()}/report?download=true").status_code == 404


def test_current_chunk_comes_from_durable_state_even_when_retrying_an_earlier_chunk(settings: Settings) -> None:
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(InferenceModel()))) as client:
        analysis_id = upload_ready(client)
        database: Database = client.app.state.database
        store: InferenceStore = client.app.state.inference_store
        store.queue(analysis_id, {})
        store.claim()
        first = store.next_chunk(analysis_id)
        with database.connection() as connection:
            # Done/failed totals are insufficient to infer the current ordinal.
            original = connection.execute("SELECT * FROM chunks WHERE id=?", (first["chunk_id"],)).fetchone()
            connection.execute("INSERT INTO chunks SELECT ?,analysis_id,2,start_line,end_line,start_byte,end_byte,input_tokens,status,entries_json,payload_json,created_at FROM chunks WHERE id=?", (str(uuid4()), original["id"]))
            connection.execute("INSERT INTO inference_chunks (chunk_id,analysis_id,ordinal,status) SELECT id,analysis_id,ordinal,'completed' FROM chunks WHERE analysis_id=? AND ordinal=2", (analysis_id,))
        job = client.get(f"/api/analyses/{analysis_id}").json()
        assert job["inference"]["completed_chunks"] == 1
        assert job["inference"]["current_chunk"] == 1
        with database.connection() as connection:
            connection.execute("UPDATE inference_runs SET status='partially_completed' WHERE analysis_id=?", (analysis_id,))
        assert client.get(f"/api/analyses/{analysis_id}").json()["inference"]["current_chunk"] is None


@pytest.mark.parametrize("stage", ["_merge_rates", "_finish_episode"])
def test_report_build_waits_for_a_concurrent_checkpoint_instead_of_upgrading_a_read_lock(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str,
) -> None:
    path = tmp_path / "concurrent-report.log"
    path.write_text("".join(f'192.0.2.10 - - [07/Nov/2026:12:{index // 60:02}:{index % 60:02} +0000] "GET /search?q={index}%27%20OR%201=1 HTTP/1.1" 403 12\n' for index in range(128)))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(replace(settings, request_rate_threshold=3))) as client:
        database = client.app.state.database
        correlator = client.app.state.report_service.correlator
        original = getattr(correlator, stage)
        injected = []

        def race(writer, value):
            if writer.in_transaction:
                return original(writer, value)
            locked = Event()

            def checkpoint():
                with database.connection() as other:
                    other.execute("BEGIN IMMEDIATE")
                    other.execute("INSERT OR REPLACE INTO app_metadata (key,value) VALUES ('concurrent_test_checkpoint','1')")
                    locked.set()
                    time.sleep(0.08)

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(checkpoint)
                assert locked.wait(timeout=5)
                injected.append(stage)
                original(writer, value)
                future.result(timeout=5)

        monkeypatch.setattr(correlator, stage, race)
        response = client.get(f"/api/analyses/{analysis_id}/report")
        assert response.status_code == 200, response.text
        assert injected
        report = response.json()
        assert report["total_findings"] == 1
        assert len(report["incidents"][0]["evidence"]) == 128
