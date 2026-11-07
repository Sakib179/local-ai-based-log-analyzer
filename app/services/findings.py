"""Bounded JSON recovery and strict evidence verification, never execution."""

import json
import re
from pathlib import Path

from pydantic import ValidationError

from app.errors import AppError
from app.schemas import FindingBatch
from app.services.parsing import Evidence, extract_fields


class InvalidFindingResponse(AppError):
    def __init__(self, code: str) -> None:
        super().__init__(502, code, "The model response failed JSON or evidence validation.")


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("Non-finite JSON number")


DECODER = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)


def parse_findings(content: str) -> tuple[FindingBatch, str]:
    text = content.strip()
    if not text or len(text.encode("utf-8")) > 32768:
        raise InvalidFindingResponse("empty_or_oversized_content")
    mode = "strict"
    try:
        value = DECODER.decode(text)
    except (ValueError, RecursionError):
        fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
        if fenced:
            text, mode = fenced[1].strip(), "code_fence"
        try:
            value = DECODER.decode(text)
        except (ValueError, RecursionError):
            # Only try the first object. Never select a nested object from a
            # truncated response or cherry-pick among multiple JSON documents.
            start = text.find("{")
            if start < 0:
                raise InvalidFindingResponse("invalid_json") from None
            try:
                value, end = DECODER.raw_decode(text, start)
            except (ValueError, RecursionError):
                raise InvalidFindingResponse("invalid_json") from None
            if re.search(r"[{}\[\]]", text[:start] + text[end:]):
                raise InvalidFindingResponse("ambiguous_json")
            mode = "object_extraction"
    try:
        return FindingBatch.model_validate(value), mode
    except ValidationError:
        raise InvalidFindingResponse("invalid_finding_schema") from None


def evidence_from_records(records: list[dict]) -> list[Evidence]:
    return [Evidence(
        r["line_number"], r["start_char"], r["start_byte"], r["raw"], r["fragment"], r.get("continues", False)
    ) for r in records]


def verify_original(path: Path, entries: list[Evidence]) -> None:
    """Check bounded ranges against the actual upload, including after a restart."""
    with path.open("rb") as source:
        for entry in entries:
            expected = entry.raw.encode("utf-8")
            source.seek(entry.start_byte)
            if source.read(len(expected)) != expected:
                raise AppError(409, "evidence_changed", "Original log evidence is missing or has changed.")


def validate_evidence(batch: FindingBatch, entries: list[Evidence]) -> None:
    by_line: dict[int, list[str]] = {}
    previous: Evidence | None = None
    for entry in entries:
        groups = by_line.setdefault(entry.line_number, [])
        if previous and previous.line_number == entry.line_number and previous.start_char + len(previous.raw) == entry.start_char:
            groups[-1] += entry.raw
        else:
            groups.append(entry.raw)
        previous = entry
    for finding in batch.findings:
        excerpts = []
        for citation in finding.evidence:
            if citation.line not in by_line:
                raise InvalidFindingResponse("unknown_evidence_line")
            if not any(citation.excerpt in raw for raw in by_line[citation.line]):
                raise InvalidFindingResponse("evidence_excerpt_mismatch")
            excerpts.append(citation.excerpt)
        if finding.identifier:
            entity = re.compile(r"(?<![\w.:-])" + re.escape(finding.identifier) + r"(?![\w.:-])")
            if not any(entity.search(excerpt) for excerpt in excerpts):
                raise InvalidFindingResponse("identifier_not_in_evidence")
        # Reject invented IPs in narrative fields as well as the identifier.
        narrative = " ".join([finding.attack_type, finding.reason, finding.suggested_action])
        for address in extract_fields(narrative).get("ip_addresses", []):
            if not any(address in excerpt for excerpt in excerpts):
                raise InvalidFindingResponse("invented_ip_address")
