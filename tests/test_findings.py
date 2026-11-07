import json
from pathlib import Path

import pytest

from app.errors import AppError
from app.services.findings import InvalidFindingResponse, parse_findings, validate_evidence, verify_original
from app.services.parsing import Evidence


def sample_finding(line: int = 1, excerpt: str = "Failed login for alice from 192.0.2.4") -> dict:
    return {
        "attack_type": "Possible brute-force attempt", "severity": "High", "identifier": "192.0.2.4",
        "evidence": [{"line": line, "excerpt": excerpt}],
        "reason": "Repeated authentication failures.", "suggested_action": "Investigate and rate-limit the source.",
        "confidence": "possible",
    }


@pytest.mark.parametrize("wrapper,mode", [("{}", "strict"), ("```json\n{}\n```", "code_fence"), ("Result:\n{}\nDone.", "object_extraction")])
def test_strict_json_and_bounded_recovery(wrapper: str, mode: str) -> None:
    content = json.dumps({"findings": [sample_finding()]})
    batch, actual_mode = parse_findings(wrapper.format(content))
    validate_evidence(batch, [Evidence(1, 0, 0, "Failed login for alice from 192.0.2.4\n", False)])
    assert actual_mode == mode
    assert batch.findings[0].severity == "High"


def test_empty_findings_are_valid() -> None:
    batch, _ = parse_findings('{"findings": []}')
    validate_evidence(batch, [])
    assert not batch.findings


@pytest.mark.parametrize("content", [
    "", "not JSON", '{"findings":[', '{"findings":[{"findings":[]}]} broken',
    '{"findings":[]} {"findings":[]}', '[{"findings":[]}]',
    '{"findings":[],"findings":[]}', '{"findings":NaN}',
    '{"findings":[],"unexpected":1}',
])
def test_invalid_ambiguous_or_truncated_json_is_rejected(content: str) -> None:
    with pytest.raises(InvalidFindingResponse):
        parse_findings(content)


@pytest.mark.parametrize("field,value", [("severity", "Urgent"), ("reason", " "), ("suggested_action", ""), ("confidence", "confirmed")])
def test_contract_rejects_unsupported_values(field: str, value: str) -> None:
    finding = sample_finding()
    finding[field] = value
    with pytest.raises(InvalidFindingResponse):
        parse_findings(json.dumps({"findings": [finding]}))


@pytest.mark.parametrize("change,code", [
    ({"line": 99}, "unknown_evidence_line"), ({"excerpt": "Invented evidence"}, "evidence_excerpt_mismatch"),
])
def test_citations_must_match_the_supplied_original_line(change: dict, code: str) -> None:
    finding = sample_finding()
    finding["evidence"][0].update(change)
    batch, _ = parse_findings(json.dumps({"findings": [finding]}))
    with pytest.raises(InvalidFindingResponse) as error:
        validate_evidence(batch, [Evidence(1, 0, 0, "Failed login for alice from 192.0.2.4\n", False)])
    assert error.value.code == code


@pytest.mark.parametrize("identifier", ["192.0.2.99", "92.0.2.4", "bob"])
def test_identifier_must_really_occur_in_the_cited_evidence(identifier: str) -> None:
    finding = sample_finding()
    finding["identifier"] = identifier
    batch, _ = parse_findings(json.dumps({"findings": [finding]}))
    with pytest.raises(InvalidFindingResponse, match="evidence validation"):
        validate_evidence(batch, [Evidence(1, 0, 0, "Failed login for alice from 192.0.2.4\n", False)])


def test_invented_ip_in_narrative_is_rejected() -> None:
    finding = sample_finding()
    finding["reason"] = "The source 192.0.2.99 is suspicious."
    batch, _ = parse_findings(json.dumps({"findings": [finding]}))
    with pytest.raises(InvalidFindingResponse) as error:
        validate_evidence(batch, [Evidence(1, 0, 0, "Failed login for alice from 192.0.2.4\n", False)])
    assert error.value.code == "invented_ip_address"


def test_cannot_validate_an_excerpt_across_a_missing_fragment() -> None:
    finding = sample_finding(excerpt="Failed login for alice from 192.0.2.4")
    batch, _ = parse_findings(json.dumps({"findings": [finding]}))
    entries = [Evidence(1, 0, 0, "Failed login for ", True), Evidence(1, 100, 100, "alice from 192.0.2.4", True)]
    with pytest.raises(InvalidFindingResponse):
        validate_evidence(batch, entries)


def test_original_file_is_checked_without_trusting_persisted_raw_text(tmp_path: Path) -> None:
    path = tmp_path / "source.log"
    path.write_bytes(b"original evidence\n")
    verify_original(path, [Evidence(1, 0, 0, "original evidence\n", False)])
    with pytest.raises(AppError) as error:
        verify_original(path, [Evidence(1, 0, 0, "changed evidence\n", False)])
    assert error.value.code == "evidence_changed"
