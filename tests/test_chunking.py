import asyncio
import json
from pathlib import Path

import pytest

from app.errors import AppError
from app.services.chunking import Chunker
from app.services.parsing import READ_CHARS, extract_fields, iter_evidence
from app.services.prompts import OUTPUT_TOKENS, SAFETY_TOKENS, PromptBuilder


class FakeTokenizer:
    """Deterministic test double; production always calls llama.cpp."""
    def __init__(self) -> None:
        self.calls = 0

    @staticmethod
    def count(payload: dict) -> int:
        # Simulated chat overhead plus all messages, including JSON labels and context.
        return 24 + (len(json.dumps(payload["messages"], ensure_ascii=False).encode()) + 3) // 4

    async def count_input_tokens(self, payload: dict) -> int:
        self.calls += 1
        return self.count(payload)


def collect(path: Path, tokenizer: FakeTokenizer, prompt: PromptBuilder | None = None,
            context: int = 2048) -> list:
    async def run() -> list:
        return [chunk async for chunk in Chunker(tokenizer, prompt or PromptBuilder(), context).chunks(path)]
    return asyncio.run(run())


def assert_coverage(chunks: list, raw: str) -> None:
    source_lines = raw.splitlines(keepends=True)
    entries = [e for chunk in chunks for e in chunk.entries]
    assert "".join(e.raw for e in entries) == raw
    next_byte = 0
    for entry in entries:
        assert entry.start_byte == next_byte
        next_byte = entry.end_byte
        assert source_lines[entry.line_number - 1][entry.start_char:entry.start_char + len(entry.raw)] == entry.raw
    assert next_byte == len(raw.encode())
    for chunk in chunks:
        assert chunk.input_tokens == FakeTokenizer.count(chunk.payload)
        assert chunk.input_tokens + OUTPUT_TOKENS + SAFETY_TOKENS <= 2048


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_original_lines_blank_lines_bom_and_unicode_are_lossless(tmp_path: Path, ending: str) -> None:
    raw = f"\ufefffirst{ending}{ending}用户 alice failed login{ending}last without newline"
    path = tmp_path / "input.log"
    path.write_bytes(raw.encode())
    entries = list(iter_evidence(path))
    assert [e.line_number for e in entries] == [1, 2, 3, 4]
    assert all(not e.fragment for e in entries)
    assert_coverage(collect(path, FakeTokenizer()), raw)


def test_very_long_single_line_is_split_and_marked_without_losing_content(tmp_path: Path) -> None:
    raw = ("用户🔒 deny 192.0.2.1 " * 3000) + "\r\nsecond line\n"
    path = tmp_path / "long.log"
    path.write_bytes(raw.encode())
    chunks = collect(path, FakeTokenizer())
    assert len(chunks) > 10
    fragments = [e for c in chunks for e in c.entries if e.line_number == 1]
    assert all(e.fragment for e in fragments)
    assert fragments[0].start_char == 0
    assert fragments[-1].raw.endswith("\r\n")
    assert_coverage(chunks, raw)


def test_crlf_at_reader_boundary_does_not_create_a_phantom_line(tmp_path: Path) -> None:
    raw = "a" * (READ_CHARS - 1) + "\r\nnext\r\n"
    path = tmp_path / "boundary.txt"
    path.write_bytes(raw.encode())
    assert [e.line_number for e in iter_evidence(path)] == [1, 2]
    assert_coverage(collect(path, FakeTokenizer()), raw)


def test_whole_entries_are_packed_without_fragmentation_when_they_fit(tmp_path: Path) -> None:
    raw = "".join(f"line {i}: failed login for alice from 192.0.2.1\n" for i in range(300))
    path = tmp_path / "normal.log"
    path.write_text(raw)
    chunks = collect(path, FakeTokenizer())
    assert len(chunks) > 1
    assert all(not e.fragment for c in chunks for e in c.entries)
    assert_coverage(chunks, raw)


def test_reader_segments_are_rejoined_when_a_long_whole_entry_fits(tmp_path: Path) -> None:
    class CompressingTokenizer(FakeTokenizer):
        @staticmethod
        def count(payload: dict) -> int:
            return 30 + len(json.dumps(payload["messages"]).encode()) // 16

    path = tmp_path / "compressible.log"
    raw = "a" * 8000 + "\n"
    path.write_text(raw)
    chunks = collect(path, CompressingTokenizer())
    assert len(chunks) == 1
    assert len(chunks[0].entries) == 1
    assert chunks[0].entries[0].raw == raw
    assert not chunks[0].entries[0].fragment


def test_saved_context_system_instructions_and_output_are_in_budget(tmp_path: Path) -> None:
    path = tmp_path / "context.log"
    raw = "failed login for alice\n" * 100
    path.write_text(raw)
    prompt = PromptBuilder(system_prompt="Only use evidence. " * 25, saved_context="previous context " * 100)
    chunks = collect(path, FakeTokenizer(), prompt)
    assert_coverage(chunks, raw)
    for chunk in chunks:
        assert chunk.payload["messages"][0]["content"] == prompt.system_prompt
        assert json.loads(chunk.payload["messages"][1]["content"])["saved_context"] == prompt.saved_context
        assert chunk.payload["max_tokens"] == 384
    with pytest.raises(AppError, match="leave no log budget"):
        collect(path, FakeTokenizer(), PromptBuilder(saved_context="x" * 10000))


def test_approximately_20000_token_log_uses_bounded_search(tmp_path: Path) -> None:
    raw = "".join(
        f'192.0.2.1 - alice [07/Nov/2026:12:00:00 +0600] "GET /api/orders/{i} HTTP/1.1" 401 123 "-" "agent"\n'
        for i in range(800)
    )
    assert 18000 <= len(raw.encode()) // 4 <= 24000
    path = tmp_path / "large.log"
    path.write_text(raw)
    tokenizer = FakeTokenizer()
    chunks = collect(path, tokenizer)
    assert_coverage(chunks, raw)
    assert tokenizer.calls <= 8 * len(chunks) + 2


def test_processing_never_uses_unbounded_file_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "bounded.log"
    raw = "a" * (READ_CHARS * 20) + "\n"
    path.write_text(raw)
    original_open = Path.open

    class GuardedReader:
        def __init__(self, source):
            self.source = source
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.source.close()
        def readline(self, size: int = -1) -> str:
            assert 0 < size <= READ_CHARS
            return self.source.readline(size)
        def read(self, *_args):
            pytest.fail("Unbounded file read attempted")

    def guarded_open(file_path, *args, **kwargs):
        source = original_open(file_path, *args, **kwargs)
        return GuardedReader(source) if file_path == path else source

    monkeypatch.setattr(Path, "open", guarded_open)
    assert_coverage(collect(path, FakeTokenizer()), raw)


def test_common_access_and_auth_fields_and_unknown_format() -> None:
    access = extract_fields('192.0.2.1 - alice [07/Nov/2026:12:00:00 +0600] "GET /private?q=1 HTTP/1.1" 403 12\n')
    assert access["timestamp"] == "07/Nov/2026:12:00:00 +0600"
    assert access["username"] == "alice"
    assert access["path"] == "/private?q=1"
    assert access["status"] == 403
    assert access["ip_addresses"] == ["192.0.2.1"]
    auth = extract_fields("Nov  7 12:00:00 host sshd[12]: Failed password for invalid user bob from 2001:db8::2 port 22 ssh2\n")
    assert auth["timestamp"] == "Nov  7 12:00:00"
    assert auth["username"] == "bob"
    assert auth["ip_addresses"] == ["2001:db8::2"]
    assert extract_fields("arbitrary unknown log; $(touch /tmp/never-execute)") == {}
