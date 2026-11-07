"""Explicitly opt in to one small real local Qwen security analysis."""

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.schemas import FindingBatch
from test_inference import upload_ready, wait_inference

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("RUN_INFERENCE_INTEGRATION") != "1", reason="Set RUN_INFERENCE_INTEGRATION=1 for real local inference"),
]


def test_real_local_qwen_inference(settings: Settings) -> None:
    local = Settings.from_env()
    settings = replace(settings, model_base_url=local.model_base_url, model_alias=local.model_alias,
                       inference_timeout_seconds=180, inference_max_attempts=2, log_level="WARNING")
    raw = "".join(
        f"2026-11-07T12:00:0{i}Z Failed login for alice from 192.0.2.4\n" for i in range(1, 7)
    ).encode()
    with TestClient(create_app(settings)) as client:
        if client.get("/api/model/health").status_code != 200:
            pytest.skip("The separately started local llama.cpp server is unavailable")
        analysis_id = upload_ready(client, raw)
        client.post(f"/api/analyses/{analysis_id}/start")
        job = wait_inference(client, analysis_id, timeout=200)
        assert job["status"] == "completed", job
        candidates = client.get(f"/api/analyses/{analysis_id}/findings").json()["findings"]
        batch = FindingBatch.model_validate({"findings": [candidate["finding"] for candidate in candidates]})
        attempts = client.get(f"/api/analyses/{analysis_id}/attempts").json()["attempts"]
        assert any(a["status"] == "completed" for a in attempts)
        assert all(a["input_tokens"] + 448 <= 2048 for a in attempts if a["input_tokens"] is not None)
        sample = batch.model_dump()
        print("SAMPLE_VALIDATED_RESPONSE=" + json.dumps(sample, ensure_ascii=False))
        if sample_path := os.environ.get("PHASE3_SAMPLE_PATH"):
            Path(sample_path).write_text(json.dumps(sample, indent=2, ensure_ascii=False) + "\n")
