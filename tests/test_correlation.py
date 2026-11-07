import hashlib
import json
import os
from dataclasses import asdict, replace
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import CHAT_COMPLETIONS_PATH, INPUT_TOKENS_PATH, Settings
from app.database import Database
from app.event_database import CORRELATION_TABLES, EventStore, index_chunk_events
from app.inference_database import InferenceStore
from app.main import create_app
from app.services.event_parsing import parse_events, parse_timestamp
from app.services.parsing import iter_evidence
from app.services.prompts import PromptBuilder
from fixtures.cross_chunk_auth import AUTH_LINES, SOURCE_BOUNDARIES, write_cross_chunk_log
from test_chunking import FakeTokenizer
from test_inference import wait_inference
from test_uploads import wait_for_job
from app.services.parsing import Evidence


class ReportModel:
    """Synthetic tests only. All application correlation remains computed Python."""
    def __init__(self, *, sql: bool = False, fail_after: int | None = None, generic_error_attack: bool = False):
        self.sql, self.fail_after, self.generic_error_attack = sql, fail_after, generic_error_attack
        self.calls = 0
        self.contexts = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/slots":
            return httpx.Response(200, json=[{"is_processing": False}])
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        payload = json.loads(request.content)
        if request.url.path == INPUT_TOKENS_PATH:
            return httpx.Response(200, json={"input_tokens": FakeTokenizer.count(payload)})
        assert request.url.path == CHAT_COMPLETIONS_PATH
        assert FakeTokenizer.count(payload) + 448 <= 2048
        self.calls += 1
        user = json.loads(payload["messages"][1]["content"])
        self.contexts.append(user["saved_context"])
        if self.fail_after is not None and self.calls > self.fail_after:
            return httpx.Response(503)
        findings = []
        if self.sql or self.generic_error_attack:
            entry = user["entries"][0]
            findings = [{
                "attack_type": "Possible SQL injection", "severity": "High", "identifier": "192.0.2.10",
                "evidence": [{"line": entry["line"], "excerpt": entry["raw"].strip()}],
                "reason": "Suspicious request payload.", "suggested_action": "Investigate the source and validate queries.", "confidence": "possible",
            }]
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"findings": findings})}, "finish_reason": "stop"}]})


def seed_prepared(settings: Settings, path: Path, boundaries: list[int] | None = None) -> tuple[str, list[str]]:
    """Partition a synthetic fixture explicitly; do not change production packing."""
    assert settings.database_path is not None
    database = Database(settings.database_path)
    database.initialize()
    analysis_id = str(uuid4())
    database.create_analysis(analysis_id, path, {"context_tokens": 2048, "prompt": asdict(PromptBuilder())})
    digest = hashlib.sha256()
    total_bytes, last_line = 0, 0
    chunks = []
    source = iter_evidence(path)
    try:
        for end_line in boundaries or [10**9]:
            entries = list(islice(source, end_line - last_line))
            if not entries:
                continue
            for entry in entries:
                encoded = entry.raw.encode()
                digest.update(encoded)
                total_bytes += len(encoded)
            last_line = entries[-1].line_number
            chunk_id = str(uuid4())
            chunks.append(chunk_id)
            database.save_chunk(analysis_id, chunk_id, len(chunks), [e.to_record() for e in entries], PromptBuilder().build(entries), 100)
    finally:
        source.close()
    database.queue_analysis(analysis_id, path.name, total_bytes, digest.hexdigest())
    database.finish_analysis(analysis_id)
    return analysis_id, chunks


def get_report(client: TestClient, analysis_id: str) -> dict:
    response = client.get(f"/api/analyses/{analysis_id}/report")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    return response.json()


def auth_record(minute: int, *, ip: str = "192.0.2.10", user: str = "admin", success: bool = False, hour: int = 12) -> str:
    kind = "Successful" if success else "Failed"
    return f"2026-11-07T{hour:02d}:{minute:02d}:00Z {kind} login from {ip} for user {user}.\n"


def test_distant_chunk_1_5_10_authentication_is_one_final_finding(settings: Settings, tmp_path: Path) -> None:
    settings = replace(settings, log_level="WARNING", inference_retry_backoff_seconds=0)
    path = tmp_path / "cross_chunk_auth.log"
    write_cross_chunk_log(path)
    analysis_id, chunks = seed_prepared(settings, path, SOURCE_BOUNDARIES)
    model = ReportModel()
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(model))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id, timeout=60)["status"] == "completed"
        report = get_report(client, analysis_id)
        assert report["processed_chunks"] == 10
        assert report["total_findings"] == 1
        assert report["finding_counts_by_severity"]["High"] == 1
        incident = report["incidents"][0]
        assert incident["identifier"] == "192.168.1.5" and incident["username"] == "admin"
        assert incident["metrics"]["failures_before_success"] == 5
        assert "followed by successful authentication" in incident["title"]
        assert incident["risk_status"] == "inferred_possible"
        assert {e["line"] for e in incident["evidence"]} == set(AUTH_LINES)
        assert {e["chunk_ordinal"] for e in incident["evidence"]} == {1, 5, 10}
        assert {e["chunk_id"] for e in incident["evidence"]} == {chunks[0], chunks[4], chunks[9]}
        assert report["report_complete"] is True
        assert get_report(client, analysis_id) == report  # stable cached report and IDs
        assert any('"failed":5' in context and '"first_line":100' in context for context in model.contexts)
        assert all(len(context) <= 512 for context in model.contexts)
        if destination := os.environ.get("PHASE4_REPORT_PATH"):
            Path(destination).write_text(json.dumps(report, indent=2) + "\n")
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(ReportModel()))) as client:
        assert get_report(client, analysis_id)["incidents"][0]["id"] == incident["id"]


def test_repeated_validated_sql_findings_merge_with_deterministic_evidence(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "sql.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12\n'
                    '192.0.2.10 - - [07/Nov/2026:12:00:03 +0000] "GET /search?q=2%27%20OR%202=2 HTTP/1.1" 403 12\n')
    analysis_id, _ = seed_prepared(settings, path, [1, 2])
    with TestClient(create_app(replace(settings, log_level="WARNING"), model_transport=httpx.MockTransport(ReportModel(sql=True)))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        assert client.get(f"/api/analyses/{analysis_id}/findings").json()["total"] == 2
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        incident = report["incidents"][0]
        assert incident["category"] == "sql_injection"
        assert incident["detection_methods"] == ["deterministic", "validated_ai"]
        assert len(incident["ai_finding_ids"]) == 2
        assert [e["line"] for e in incident["evidence"]] == [1, 2]


@pytest.mark.parametrize("different", ["source", "account", "time"])
def test_unrelated_incidents_remain_separate(settings: Settings, tmp_path: Path, different: str) -> None:
    raw = "".join(auth_record(i) for i in range(5)) + auth_record(6, success=True)
    options = {"ip": "192.0.2.20"} if different == "source" else {"user": "bob"} if different == "account" else {"hour": 14}
    raw += "".join(auth_record(i, **options) for i in range(5)) + auth_record(6, success=True, **options)
    path = tmp_path / "separate.log"
    path.write_text(raw)
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 2
        assert all("followed by successful authentication" in finding["title"] for finding in report["incidents"])


def test_missing_timestamps_use_line_order_without_confirming_compromise(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "missing-clock.log"
    write_cross_chunk_log(path, timestamps=False)
    analysis_id, _ = seed_prepared(settings, path, SOURCE_BOUNDARIES)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        finding = report["incidents"][0]
        assert finding["time_basis"] == "line_order_only"
        assert finding["severity"] == "Medium"
        assert finding["metrics"]["failures_before_success"] == 5
        assert any("elapsed time" in limit for limit in report["limitations"])


def test_duplicates_preserve_references_without_inflating_event_counts(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "duplicates.log"
    path.write_text(auth_record(0) * 10 + auth_record(1, success=True))
    analysis_id, chunks = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        for _ in range(3):
            client.app.state.event_store.ensure_indexed(analysis_id)
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 0
        with client.app.state.database.connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM security_events WHERE analysis_id=? AND event_type='auth_failure'", (analysis_id,)).fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM event_evidence WHERE analysis_id=?", (analysis_id,)).fetchone()[0] == 11


def test_rolling_window_handles_threshold_near_an_old_anchor_boundary(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "rolling.log"
    path.write_text("".join(auth_record(i) for i in [0, 25, 26, 27, 29, 30]) + auth_record(31, success=True))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        incident = get_report(client, analysis_id)["incidents"][0]
        assert incident["metrics"]["failures_before_success"] == 5
        assert incident["severity"] == "High"


def test_late_success_does_not_imply_compromise(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "late.log"
    path.write_text("".join(auth_record(i) for i in range(5)) + auth_record(0, hour=14, success=True))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert report["incidents"][0]["metrics"]["qualifying_successes"] == 0


def test_ordinary_404_500_and_sql_debug_errors_are_not_attacks(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "normal.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /missing HTTP/1.1" 404 12\n'
                    '192.0.2.10 - - [07/Nov/2026:12:00:01 +0000] "GET /health HTTP/1.1" 500 12\n'
                    "ERROR normal database query failed: SELECT name FROM users\n")
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        assert get_report(client, analysis_id)["total_findings"] == 0


def test_ai_attack_label_on_generic_error_is_not_enough(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "generic-ai.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /missing HTTP/1.1" 404 12\n')
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(ReportModel(generic_error_attack=True)))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        assert client.get(f"/api/analyses/{analysis_id}/findings").json()["total"] == 1
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 0
        assert any("excluded" in limitation for limitation in report["limitations"])


def test_sensitive_path_scan_and_request_rate(settings: Settings, tmp_path: Path) -> None:
    paths = ["/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/", "/cgi-bin/test"]
    path = tmp_path / "scan.log"
    path.write_text("".join(f'192.0.2.10 - - [07/Nov/2026:12:00:0{i} +0000] "GET {target} HTTP/1.1" 404 12\n' for i, target in enumerate(paths)))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(replace(settings, request_rate_threshold=3))) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1  # related rate evidence is combined with scanning
        incident = report["incidents"][0]
        assert incident["category"] == "scanning"
        assert incident["metrics"]["distinct_sensitive_paths"] == 5
        assert incident["metrics"]["related_request_rate"]["http_request"] == 5


def test_partial_ai_failure_cannot_erase_correlated_events_or_completed_findings(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "partial.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12\n'
                    '192.0.2.10 - - [07/Nov/2026:12:00:03 +0000] "GET /search?q=2%27%20OR%202=2 HTTP/1.1" 403 12\n')
    analysis_id, _ = seed_prepared(settings, path, [1, 2])
    options = replace(settings, inference_retry_backoff_seconds=0, log_level="WARNING")
    with TestClient(create_app(options, model_transport=httpx.MockTransport(ReportModel(sql=True, fail_after=1)))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "partially_completed"
        report = get_report(client, analysis_id)
        assert report["analysis_status"] == "partially_completed"
        assert report["total_findings"] == 1
        assert len(report["incidents"][0]["ai_finding_ids"]) == 1
        assert [e["line"] for e in report["incidents"][0]["evidence"]] == [1, 2]
        assert report["analysis_errors"]
        assert report["report_complete"] is False


def test_report_backfills_phase_three_without_regenerating_completed_ai(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "legacy-sql.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12\n'
                    '192.0.2.10 - - [07/Nov/2026:12:00:03 +0000] "GET /search?q=2%27%20OR%202=2 HTTP/1.1" 403 12\n')
    analysis_id, _ = seed_prepared(settings, path, [1, 2])
    model = ReportModel(sql=True)
    with TestClient(create_app(replace(settings, log_level="WARNING"), model_transport=httpx.MockTransport(model))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        old_ids = {item["id"] for item in client.get(f"/api/analyses/{analysis_id}/findings").json()["findings"]}
    assert settings.database_path is not None
    database = Database(settings.database_path)
    with database.connection() as connection:
        for table in CORRELATION_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("UPDATE app_metadata SET value='3' WHERE key='schema_version'")
    count_before = model.calls
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(model))) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert set(report["incidents"][0]["ai_finding_ids"]) == old_ids
        assert report["processed_chunks"] == 2
        assert model.calls == count_before
        assert client.app.state.database.get_metadata("schema_version") == "4"


def test_later_context_never_includes_future_or_unrelated_account_target_records(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "memory.log"
    records = [
        {"message": "Failed login", "source_ip": "192.0.2.10", "user": "bob", "target": "vpn"},
        {"message": "Failed login", "source_ip": "192.0.2.20", "user": "admin", "target": "vpn"},
        {"message": "Failed login", "source_ip": "192.0.2.10", "user": "admin", "target": "vpn"},
        {"message": "Failed login", "source_ip": "192.0.2.10", "user": "admin", "target": "ssh"},
        {"message": "Successful login", "source_ip": "192.0.2.10", "user": "admin", "target": "vpn"},
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    analysis_id, _ = seed_prepared(settings, path)
    assert settings.database_path is not None
    events = EventStore(Database(settings.database_path))
    evidence = list(iter_evidence(path))
    assert events.compact_context(analysis_id, [evidence[3]]) == ""
    prior = json.loads(events.compact_context(analysis_id, [evidence[4]]))["prior_observations"]
    assert len(prior) == 1
    assert prior[0]["source"] == "192.0.2.10" and prior[0]["account"] == "admin" and prior[0]["target"] == "vpn"
    assert prior[0]["failed"] == 1 and prior[0]["successful"] == 0
    assert prior[0]["first_line"] == prior[0]["last_line"] == 3


def test_same_ip_different_sql_targets_are_different_incidents(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "targets.log"
    path.write_text("".join(
        f'192.0.2.10 - - [07/Nov/2026:12:00:0{i} +0000] "GET {target}?id={i}%27%20OR%201=1 HTTP/1.1" 403 12\n'
        for i, target in enumerate(["/search", "/search", "/admin", "/admin"])
    ))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 2
        assert {finding["target"] for finding in report["incidents"]} == {"/search", "/admin"}


def test_clock_regression_cannot_turn_an_earlier_login_into_a_later_success(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "backward.log"
    path.write_text("".join(auth_record(i) for i in [20, 21, 22, 23, 24]) + auth_record(10, success=True))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert report["incidents"][0]["metrics"]["qualifying_successes"] == 0


def test_failures_spread_across_hours_do_not_satisfy_a_thirty_minute_threshold(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "spread.log"
    path.write_text("".join(auth_record(minute, hour=hour) for hour, minute in [(12, 0), (12, 20), (12, 40), (13, 0), (13, 20)]) + auth_record(25, hour=13, success=True))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        assert get_report(client, analysis_id)["total_findings"] == 0


def test_http_200_on_login_is_not_treated_as_successful_authentication(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "http-login.log"
    path.write_text("".join(f'192.0.2.10 - - [07/Nov/2026:12:00:0{i} +0000] "POST /login?attempt={i} HTTP/1.1" 401 12\n' for i in range(5))
                    + '192.0.2.10 - - [07/Nov/2026:12:00:06 +0000] "POST /login HTTP/1.1" 200 12\n')
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert report["incidents"][0]["metrics"]["qualifying_successes"] == 0


def test_rates_require_timestamps_and_identical_targets_do_not_fake_a_scan(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "no-rate.log"
    path.write_text("".join(json.dumps({"source_ip": "192.0.2.10", "path": f"/.env?attempt={i}", "status": 404}) + "\n" for i in range(10)))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(replace(settings, request_rate_threshold=3))) as client:
        assert get_report(client, analysis_id)["total_findings"] == 0


def test_related_denials_rates_and_sql_evidence_are_deduplicated(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "related.log"
    path.write_text("".join(f'192.0.2.10 - - [07/Nov/2026:12:00:0{i} +0000] "GET /search?q={i}%27%20OR%201=1 HTTP/1.1" 403 12\n' for i in range(5)))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(replace(settings, request_rate_threshold=3))) as client:
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        incident = report["incidents"][0]
        assert incident["severity"] == "High"
        assert len(incident["evidence"]) == 5
        assert incident["confirmed_log_events"] == {"sql_injection_pattern": 5, "http_request": 5, "unauthorized": 5}


def test_report_refresh_adds_ai_support_without_changing_incident_identity(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "update.log"
    path.write_text('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201=1 HTTP/1.1" 403 12\n')
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(ReportModel(sql=True)))) as client:
        first = get_report(client, analysis_id)
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        second = get_report(client, analysis_id)
        assert first["incidents"][0]["id"] == second["incidents"][0]["id"]
        assert second["incidents"][0]["detection_methods"] == ["deterministic", "validated_ai"]
        assert first["report_complete"] is False and second["report_complete"] is True


def test_report_missing_analysis_is_consistent_json_404(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(f"/api/analyses/{uuid4()}/report")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "analysis_not_found"


def test_stream_snapshot_can_resume_sequentially_on_different_worker_threads(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "threaded-report.log"
    path.write_text("".join(auth_record(i) for i in range(5)) + auth_record(6, success=True))
    analysis_id, _ = seed_prepared(settings, path)
    with TestClient(create_app(settings)) as client:
        service = client.app.state.report_service
        service.prepare(analysis_id)
        stream = service.stream(analysis_id)
        parts = []
        with ThreadPoolExecutor(max_workers=1) as first, ThreadPoolExecutor(max_workers=1) as second:
            pools = [first, second]
            while True:
                try:
                    parts.append(pools[len(parts) % 2].submit(next, stream).result())
                except StopIteration:
                    break
        assert json.loads("".join(parts))["total_findings"] == 1


def test_memory_excludes_old_time_windows_and_future_clock_values(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "context-time.log"
    path.write_text(auth_record(0, hour=9) + auth_record(0, hour=13) + auth_record(5, hour=12))
    analysis_id, _ = seed_prepared(settings, path)
    assert settings.database_path is not None
    assert EventStore(Database(settings.database_path)).compact_context(analysis_id, [list(iter_evidence(path))[2]]) == ""


def test_ai_only_assessments_merge_and_use_order_independent_capped_severity(settings: Settings, tmp_path: Path) -> None:
    class AuthModel(ReportModel):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            response = super().__call__(request)
            if request.url.path != CHAT_COMPLETIONS_PATH:
                return response
            entry = json.loads(json.loads(request.content)["messages"][1]["content"])["entries"][0]
            finding = {"attack_type": "Possible brute-force activity", "severity": "Low" if self.calls == 1 else "High",
                       "identifier": "192.0.2.10", "evidence": [{"line": entry["line"], "excerpt": entry["raw"].strip()}],
                       "reason": "Authentication failures warrant review.", "suggested_action": "Investigate authentication logs.", "confidence": "possible"}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"findings": [finding]})}, "finish_reason": "stop"}]})

    path = tmp_path / "ai-only.log"
    path.write_text(auth_record(0) + auth_record(1))
    analysis_id, _ = seed_prepared(settings, path, [1, 2])
    model = AuthModel()
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(model))) as client:
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        incident = get_report(client, analysis_id)["incidents"][0]
        assert incident["severity"] == "Medium"
        assert incident["detection_methods"] == ["validated_ai"]
        assert len(incident["ai_finding_ids"]) == 2
        assert any("prior_ai_assessment" in context for context in model.contexts)


def test_future_ai_reference_to_a_deduplicated_old_event_does_not_leak_into_context(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "future-ai.log"
    raw = auth_record(0)
    path.write_text(raw + "INFO heartbeat\n" + auth_record(1) + "INFO heartbeat\n" + raw)
    analysis_id, chunks = seed_prepared(settings, path, [1, 2, 3, 4, 5])
    assert settings.database_path is not None
    database = Database(settings.database_path)
    store = InferenceStore(database)
    store.queue(analysis_id, {})
    entry = list(iter_evidence(path))[4]
    store.save_unit(analysis_id, chunks[4], "000001", [entry.to_record()], PromptBuilder().build([entry]), 100)
    unit = store.next_unit(chunks[4])
    finding = {"attack_type": "Possible brute-force", "severity": "Medium", "identifier": "192.0.2.10",
               "evidence": [{"line": 5, "excerpt": entry.raw.strip()}], "reason": "Review authentication failures.",
               "suggested_action": "Investigate the source.", "confidence": "possible"}
    store.complete_unit(unit, [finding])
    context = json.loads(EventStore(database).compact_context(analysis_id, [list(iter_evidence(path))[2]]))["prior_observations"][0]
    assert context["failed"] == 1
    assert context["prior_ai_suspicions"] == 0
    assert "prior_ai_assessment" not in context


def test_real_upload_preparation_and_inference_pipeline_correlates_distant_lines(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "actual-upload.log"
    write_cross_chunk_log(path)
    model = ReportModel()
    with TestClient(create_app(replace(settings, log_level="WARNING"), model_transport=httpx.MockTransport(model))) as client:
        with path.open("rb") as source:
            response = client.post("/api/analyses", files={"file": (path.name, source, "text/plain")})
        assert response.status_code == 202
        analysis_id = response.json()["id"]
        job = wait_for_job(client, analysis_id, timeout=30)
        assert job["status"] == "ready", job
        initial = get_report(client, analysis_id)
        assert initial["total_findings"] == 1 and model.calls == 0
        assert initial["indexed_chunks"] == job["total_chunks"] > 10
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id, timeout=60)["status"] == "completed"
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert {e["line"] for e in report["incidents"][0]["evidence"]} == set(AUTH_LINES)
        assert len({e["chunk_id"] for e in report["incidents"][0]["evidence"]}) >= 3
        assert report["processed_chunks"] == job["total_chunks"]
        assert report["report_complete"] is True


def test_validated_ai_citations_can_supplement_literal_custom_json_auth_facts(settings: Settings, tmp_path: Path) -> None:
    class JsonAuthModel(ReportModel):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            response = super().__call__(request)
            if request.url.path != CHAT_COMPLETIONS_PATH:
                return response
            entry = json.loads(json.loads(request.content)["messages"][1]["content"])["entries"][0]
            finding = {"attack_type": "Possible authentication abuse", "severity": "Medium", "identifier": "192.0.2.10",
                       "evidence": [{"line": entry["line"], "excerpt": entry["raw"].strip()}],
                       "reason": "Structured records report authentication failures.", "suggested_action": "Investigate the source.", "confidence": "possible"}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"findings": [finding]})}, "finish_reason": "stop"}]})

    path = tmp_path / "custom-json.log"
    path.write_text("".join(json.dumps({"operation": "login", "result": "failure", "peer_address": "192.0.2.10", "username": "admin",
                                         "timestamp": f"2026-11-07T12:0{i}:00Z"}) + "\n" for i in range(2)))
    analysis_id, _ = seed_prepared(settings, path, [1, 2])
    with TestClient(create_app(settings, model_transport=httpx.MockTransport(JsonAuthModel()))) as client:
        assert get_report(client, analysis_id)["total_findings"] == 0
        client.post(f"/api/analyses/{analysis_id}/start")
        assert wait_inference(client, analysis_id)["status"] == "completed"
        report = get_report(client, analysis_id)
        assert report["total_findings"] == 1
        assert report["incidents"][0]["confirmed_log_events"]["auth_failure"] == 2
        with client.app.state.database.connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM security_events WHERE analysis_id=? AND origin='ai_supported'", (analysis_id,)).fetchone()[0] == 2
