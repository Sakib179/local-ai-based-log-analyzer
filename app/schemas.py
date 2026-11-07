"""Public API response contracts."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

RunState = Literal["queued", "running", "completed", "partially_completed", "failed"]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    database: Literal["ok"] = "ok"
    version: str


class ModelHealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    model: str


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class InferenceProgress(BaseModel):
    status: RunState
    total_chunks: int
    completed_chunks: int
    failed_chunks: int
    completed_units: int
    failed_units: int
    findings_count: int
    attempts: int
    retries: int
    current_chunk: int | None = None
    error: ErrorDetail | None = None
    created_at: str
    updated_at: str


class AnalysisCreated(BaseModel):
    id: str
    status: Literal["queued"] = "queued"


class AnalysisResponse(BaseModel):
    id: str
    filename: str
    size_bytes: int
    sha256: str | None
    encoding: str
    status: Literal["uploading", "queued", "processing", "ready", "running", "completed", "partially_completed", "failed"]
    preparation_status: str | None = None
    inference: InferenceProgress | None = None
    total_lines: int
    total_chunks: int
    error: ErrorDetail | None = None
    created_at: str
    updated_at: str


class ChunkResponse(BaseModel):
    id: str
    analysis_id: str
    ordinal: int
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    input_tokens: int
    status: Literal["prepared", "failed"]
    created_at: str
    inference: dict | None = None


class ChunkPage(BaseModel):
    chunks: list[ChunkResponse]
    total: int
    limit: int
    offset: int


class ChunkDetail(ChunkResponse):
    entries: list[dict]
    payload: dict


class StrictFindingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FindingEvidence(StrictFindingModel):
    line: Annotated[int, Field(ge=1)]
    excerpt: Annotated[str, StringConstraints(min_length=1, max_length=320)]

    @field_validator("excerpt")
    @classmethod
    def nonempty_excerpt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Evidence must contain text.")
        return value


class SecurityFinding(StrictFindingModel):
    attack_type: Annotated[str, StringConstraints(min_length=1, max_length=96)]
    severity: Literal["Low", "Medium", "High", "Critical"]
    identifier: Annotated[str, StringConstraints(max_length=128)]
    evidence: Annotated[list[FindingEvidence], Field(min_length=1, max_length=4)]
    reason: Annotated[str, StringConstraints(min_length=1, max_length=240)]
    suggested_action: Annotated[str, StringConstraints(min_length=1, max_length=240)]
    confidence: Literal["possible"]

    @field_validator("attack_type", "reason", "suggested_action")
    @classmethod
    def nonempty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("The field must contain text.")
        return value


class FindingBatch(StrictFindingModel):
    findings: Annotated[list[SecurityFinding], Field(max_length=3)]


class AnalysisStarted(BaseModel):
    id: str
    status: RunState
