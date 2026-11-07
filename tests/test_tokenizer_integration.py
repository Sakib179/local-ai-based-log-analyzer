"""Opt in with RUN_MODEL_INTEGRATION=1; counts tokens, never generates text."""

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import INPUT_TOKENS_PATH, Settings
from app.main import create_app
from app.services.prompts import PromptBuilder
from test_uploads import wait_for_job

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("RUN_MODEL_INTEGRATION") != "1", reason="Set RUN_MODEL_INTEGRATION=1 for local tokenizer checks"),
]


@pytest.mark.parametrize("long_line", [False, True], ids=["approximately-20000-tokens", "long-single-line"])
def test_real_tokenizer_and_streaming_preparation(
    settings: Settings, tmp_path: Path, long_line: bool
) -> None:
    configured = Settings.from_env()
    # Keep test storage temporary while using the configured local server/alias.
    settings = replace(settings, model_base_url=configured.model_base_url, model_alias=configured.model_alias, log_level="WARNING")
    line = "2026-11-07T12:00:00Z sshd: Failed password for alice from 192.0.2.4 port 22\n"
    with httpx.Client(base_url=settings.model_base_url, trust_env=False, follow_redirects=False, timeout=30) as model:
        def count(payload: dict) -> int:
            response = model.post(INPUT_TOKENS_PATH, json=payload)
            assert response.status_code == 200, response.text
            return response.json()["input_tokens"]

        # Calibrate a small sample with the real tokenizer, then write the large
        # fixture incrementally. No whole-file read or generation is necessary.
        def sample_payload(text: str) -> dict:
            return {"model": settings.model_alias, "messages": [{"role": "user", "content": text}]}

        overhead = count(sample_payload(""))
        tokens_per_line = (count(sample_payload(line * 16)) - overhead) / 16
        repetitions = max(1, round(20000 / tokens_per_line))
        source = tmp_path / "real-input.log"
        with source.open("w", encoding="utf-8", newline="") as file:
            for _ in range(repetitions):
                file.write(line.rstrip("\n") if long_line else line)
        prompt = PromptBuilder(model=settings.model_alias, saved_context="Prior evidence: repeated authentication failures.")
        with TestClient(create_app(settings, prompt_builder=prompt)) as client:
            with source.open("rb") as file:
                response = client.post("/api/analyses", files={"file": (source.name, file, "text/plain")})
            assert response.status_code == 202, response.text
            analysis_id = response.json()["id"]
            job = wait_for_job(client, analysis_id, timeout=120)
            assert job["status"] == "ready", job
            assert job["total_lines"] == (1 if long_line else repetitions)
            digest = hashlib.sha256()
            next_byte = 0
            verified = 0
            for offset in range(0, job["total_chunks"], 20):
                page = client.get(f"/api/analyses/{analysis_id}/chunks?offset={offset}&limit=20").json()
                for metadata in page["chunks"]:
                    chunk = client.get(f'/api/analyses/{analysis_id}/chunks/{metadata["id"]}').json()
                    actual = count(chunk["payload"])
                    assert actual == chunk["input_tokens"]
                    assert actual + 384 + 64 <= 2048
                    assert prompt.system_prompt == chunk["payload"]["messages"][0]["content"]
                    for entry in chunk["entries"]:
                        assert entry["start_byte"] == next_byte
                        next_byte = entry["end_byte"]
                        digest.update(entry["raw"].encode())
                        if long_line:
                            assert entry["fragment"] and entry["line_number"] == 1
                    verified += 1
            assert verified == job["total_chunks"] > 1
            assert next_byte == job["size_bytes"] == source.stat().st_size
            assert digest.hexdigest() == job["sha256"]
            print(f'Real tokenizer verified {verified} chunks, {repetitions} source units, long_line={long_line}.')
