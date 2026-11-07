"""Opt-in real-browser flows against an isolated real FastAPI application.

RUN_BROWSER_TESTS=1 uses installed Chrome, temporary SQLite/files and a mocked
local model. No model inference, downloads, Node or extra packages are involved.
"""

import asyncio
import json
import os
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import uvicorn

from app.config import CHAT_COMPLETIONS_PATH, INPUT_TOKENS_PATH, Settings
from app.main import create_app
from browser_support import Browser
from test_chunking import FakeTokenizer

pytestmark = pytest.mark.skipif(os.environ.get("RUN_BROWSER_TESTS") != "1", reason="Set RUN_BROWSER_TESTS=1 for installed-Chrome dashboard checks")


class DashboardModel:
    def __init__(self) -> None:
        self.available = True
        self.calls = 0
        self.fail_after: int | None = None

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self.available:
            raise httpx.ConnectError("Local fixture model is unavailable", request=request)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/slots":
            return httpx.Response(200, json=[{"is_processing": False}])
        payload = json.loads(request.content)
        if request.url.path == INPUT_TOKENS_PATH:
            return httpx.Response(200, json={"input_tokens": FakeTokenizer.count(payload)})
        assert request.url.path == CHAT_COMPLETIONS_PATH
        assert FakeTokenizer.count(payload) + 384 + 64 <= 2048
        self.calls += 1
        await asyncio.sleep(0.22)
        if self.fail_after is not None and self.calls > self.fail_after:
            return httpx.Response(503, json={"error": {"message": "Fixture outage"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"findings":[]}'}, "finish_reason": "stop"}]})


@pytest.fixture
def dashboard(settings: Settings, tmp_path: Path):
    model = DashboardModel()
    app = create_app(replace(settings, log_level="ERROR", inference_max_attempts=1, inference_retry_backoff_seconds=0), model_transport=httpx.MockTransport(model))
    requests: list[tuple[str, str]] = []

    @app.middleware("http")
    async def record_requests(request, call_next):
        requests.append((request.method, request.url.path))
        return await call_next(request)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline, "Isolated backend failed to start"
        time.sleep(0.02)
    browser = None
    try:
        browser = Browser(tmp_path)
        browser.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1100, "deviceScaleFactor": 1, "mobile": False})
        browser.navigate(f"http://127.0.0.1:{port}/")
        browser.wait("document.querySelector('#model-status').dataset.state === 'ok'")
        yield browser, model, requests, tmp_path, app, f"http://127.0.0.1:{port}"
        assert not browser.exceptions, browser.exceptions
    finally:
        if browser:
            browser.close()
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive()


def make_log(path: Path) -> None:
    with path.open("w") as target:
        for index in range(1, 151):
            if index <= 5:
                text = f"2026-11-07T12:0{index}:00Z Failed login from 192.0.2.10 for user admin."
                if index == 1:
                    text += ' <img src=x onerror="window.__logExecuted=1">'
            elif index == 145:
                text = "2026-11-07T12:20:00Z Successful login from 192.0.2.10 for user admin."
            elif index == 149:
                text = '198.51.100.20 - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12'
            else:
                text = f"INFO normal application heartbeat record={index}"
            target.write(text + "\n")


def prepare(browser: Browser, path: Path) -> None:
    browser.upload(path)
    browser.wait("!document.querySelector('#selected-file').hidden")
    browser.click("#upload-button")
    browser.wait("document.querySelector('#analysis-status').textContent === 'Ready to analyze'")
    browser.wait("!document.querySelector('#start-analysis').disabled")


def test_upload_start_progress_report_filters_export_and_responsive_layout(dashboard) -> None:
    browser, model, requests, directory, app, base_url = dashboard
    source = directory / "dashboard.log"
    make_log(source)
    prepare(browser, source)
    assert model.calls == 0
    assert browser.evaluate("document.querySelector('#selected-file').hidden") is True
    browser.evaluate("document.querySelector('#start-analysis').click(); document.querySelector('#start-analysis').click()")
    browser.wait("['Analyzing','Analysis queued'].includes(document.querySelector('#analysis-status').textContent)")
    assert sum(method == "POST" and path.endswith("/start") for method, path in requests) == 1
    browser.wait("document.querySelector('#analysis-status').textContent === 'Completed'", timeout=30)
    browser.wait("document.querySelector('#report-badge').textContent === 'Final report'")
    assert browser.evaluate("document.querySelector('#progress-percent').textContent") == "100%"
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "2"
    assert browser.evaluate("document.querySelector('#count-high').textContent") == "1"
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 2
    assert model.calls > 1
    browser.click(".evidence-details summary")
    browser.wait("document.querySelector('.evidence-row pre')?.textContent.includes('<img src=x')")
    assert browser.evaluate("document.querySelectorAll('.evidence-row img').length") == 0
    assert browser.evaluate("window.__logExecuted === undefined") is True

    browser.evaluate("const severity = document.querySelector('#filter-severity'); severity.value='Medium'; severity.dispatchEvent(new Event('change'))")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 1
    assert "SQL" in browser.evaluate("document.querySelector('.finding-card h3').textContent")
    browser.click("#filter-multiple")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 0
    browser.click("#clear-filters")
    browser.evaluate("const search = document.querySelector('#filter-search'); search.value='192.0.2.10'; search.dispatchEvent(new Event('input'))")
    browser.wait("document.querySelectorAll('.finding-card').length === 1")
    assert "brute-force" in browser.evaluate("document.querySelector('.finding-card h3').textContent")
    browser.click("#filter-multiple")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 1
    browser.click("#clear-filters")
    browser.evaluate("const category = document.querySelector('#filter-type'); category.value='sql_injection'; category.dispatchEvent(new Event('change'))")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 1
    browser.click("#download-report")
    deadline = time.monotonic() + 10
    while not list(directory.glob("security-report-*.json")):
        assert time.monotonic() < deadline, "JSON report did not download"
        time.sleep(0.05)
    report = json.loads(next(directory.glob("security-report-*.json")).read_text())
    assert report["total_findings"] == 2 and len(report["incidents"]) == 2
    assert report["incidents"][0]["identifier"] == "192.0.2.10"
    with httpx.Client(trust_env=False) as client:
        assert client.get(f"{base_url}/api/analyses/{report['analysis_id']}/report").json() == report

    browser.click("#clear-filters")
    # Terminal status must stop automatic polling even after more than one interval.
    status_path = f"/api/analyses/{report['analysis_id']}"
    before = requests.count(("GET", status_path))
    time.sleep(2.2)
    assert requests.count(("GET", status_path)) == before
    if destination := os.environ.get("PHASE5_SCREENSHOT_DIR"):
        browser.screenshot(Path(destination) / "dashboard-desktop.png")
    browser.call("Emulation.setDeviceMetricsOverride", {"width": 375, "height": 812, "deviceScaleFactor": 1, "mobile": True})
    browser.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
    assert browser.evaluate("document.documentElement.scrollWidth <= window.innerWidth") is True
    assert browser.evaluate("getComputedStyle(document.querySelector('.workflow-grid')).gridTemplateColumns.split(' ').length") == 1
    if destination := os.environ.get("PHASE5_SCREENSHOT_DIR"):
        browser.screenshot(Path(destination) / "dashboard-mobile.png", 375, 812)
    # Reload restores the ID, status and report, without another inference start.
    browser.call("Page.reload")
    browser.wait("document.querySelector('#report-badge')?.textContent === 'Final report'")
    assert sum(method == "POST" and path.endswith("/start") for method, path in requests) == 1


def test_validation_drag_drop_and_unavailable_model(dashboard) -> None:
    browser, model, requests, directory, app, base_url = dashboard
    browser.click("#upload-button")
    assert "Select" in browser.evaluate("document.querySelector('#upload-error').textContent")
    for filename, content, expected in [("invalid.csv", b"activity", "Unsupported"), ("empty.log", b"", "empty"), ("large.log", b"x" * (10 * 1024 * 1024 + 1), "too large")]:
        path = directory / filename
        path.write_bytes(content)
        browser.upload(path)
        assert expected in browser.evaluate("document.querySelector('#upload-error').textContent")
    assert not any(method == "POST" for method, _ in requests)
    path = directory / "binary.log"
    path.write_bytes(b"hello\x00world")
    browser.upload(path)
    browser.click("#upload-button")
    browser.wait("!document.querySelector('#upload-error').hidden && !document.querySelector('#upload-button').disabled")
    assert "binary" in browser.evaluate("document.querySelector('#upload-error').textContent").lower()
    browser.evaluate("const transfer = new DataTransfer(); transfer.items.add(new File(['INFO normal activity\\n'], 'dropped.txt', {type:'text/plain'})); document.querySelector('#dropzone').dispatchEvent(new DragEvent('drop', {bubbles:true,dataTransfer:transfer}))")
    assert browser.evaluate("document.querySelector('#selected-name').textContent") == "dropped.txt"
    browser.click("#upload-button")
    browser.wait("document.querySelector('#analysis-status').textContent === 'Ready to analyze'")
    model.available = False
    browser.click("#refresh-status")
    browser.wait("document.querySelector('#model-status').dataset.state === 'error'")
    assert browser.evaluate("document.querySelector('#start-analysis').disabled") is True
    assert "llama.cpp" in browser.evaluate("document.querySelector('#service-error').textContent")
    assert model.calls == 0
    model.available = True
    browser.click("#refresh-status")
    browser.wait("!document.querySelector('#start-analysis').disabled")
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#report-badge').textContent === 'Final report'")
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "0"
    assert browser.evaluate("document.querySelector('#empty-title').textContent") == "No suspicious activity was identified in the analyzed data."


def test_partial_failure_preserves_report_and_retry_uses_completed_checkpoints(dashboard) -> None:
    browser, model, requests, directory, app, base_url = dashboard
    source = directory / "partial.log"
    make_log(source)
    prepare(browser, source)
    model.fail_after = 1
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#analysis-status').textContent === 'Partially completed'", timeout=30)
    browser.wait("document.querySelector('#report-badge').textContent === 'Partial report'")
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "2"
    assert browser.evaluate("!document.querySelector('#analysis-error').hidden") is True
    assert "Retry unfinished" in browser.evaluate("document.querySelector('#start-analysis').textContent")
    model.fail_after = None
    browser.wait("!document.querySelector('#start-analysis').disabled")
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#report-badge').textContent === 'Final report'", timeout=30)
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "2"
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 2


def test_cards_and_expanded_evidence_are_paginated(dashboard) -> None:
    browser, model, requests, directory, app, base_url = dashboard
    source = directory / "many-events.log"
    with source.open("w") as target:
        for index in range(55):
            target.write(f"2026-11-07T12:00:{index:02}Z Failed login from 192.0.2.10 for user admin. attempt={index}\n")
        target.write("2026-11-07T12:01:00Z Successful login from 192.0.2.10 for user admin.\n")
        for index in range(1, 14):
            target.write(f'198.51.100.{index} - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12\n')
    prepare(browser, source)
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#report-badge').textContent === 'Final report'", timeout=30)
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "14"
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 12
    browser.click(".evidence-details summary")
    browser.wait("document.querySelectorAll('.evidence-row').length === 50")
    browser.click(".evidence-more")
    assert browser.evaluate("document.querySelectorAll('.evidence-row').length") == 56
    assert browser.evaluate("document.querySelector('.evidence-more').hidden") is True
    browser.click("#next-page")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 2
    assert browser.evaluate("document.querySelector('#next-page').disabled") is True
    browser.click("#previous-page")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 12
    assert browser.evaluate("document.querySelector('#previous-page').disabled") is True
    browser.click("#filter-multiple")
    assert browser.evaluate("document.querySelectorAll('.finding-card').length") == 1


def test_model_loss_after_preparation_marks_failed_job_and_preserves_report(dashboard) -> None:
    browser, model, requests, directory, app, base_url = dashboard
    source = directory / "connection-lost.log"
    make_log(source)
    prepare(browser, source)
    model.available = False
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#analysis-status').textContent === 'Failed'", timeout=30)
    browser.wait("document.querySelector('#report-badge').textContent === 'Partial report'")
    browser.wait("document.querySelector('#model-status').dataset.state === 'error'")
    assert browser.evaluate("document.querySelector('#start-analysis').disabled") is True
    assert browser.evaluate("!document.querySelector('#analysis-error').hidden") is True
    assert browser.evaluate("document.querySelector('#count-total').textContent") == "2"
    model.available = True
    browser.click("#refresh-status")
    browser.wait("!document.querySelector('#start-analysis').disabled")
    browser.click("#start-analysis")
    browser.wait("document.querySelector('#report-badge').textContent === 'Final report'", timeout=30)
