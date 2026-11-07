"""Bounded, lossless evidence iteration and best-effort common-log field extraction."""

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

READ_CHARS = 4096
ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<username>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) HTTP/[^" ]+" (?P<status>\d{3})(?:\s|$)'
)
TIMESTAMP = re.compile(r"^(?:\ufeff)?(\d{4}-\d\d-\d\d[T ][\d:.]+(?:Z|[+-]\d\d:?\d\d)?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)")
USERNAME = re.compile(r"(?:for (?:invalid user )?|user[= :]+)([A-Za-z0-9_.@-]+)")
IP_CANDIDATE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]*:[0-9A-Fa-f:.]+|\d{1,3}(?:\.\d{1,3}){3})(?![\w:])")


def extract_fields(raw: str) -> dict[str, str | int | list[str]]:
    """Keep unknown formats intact; extracted fields never replace raw evidence."""
    fields: dict[str, str | int | list[str]] = {}
    match = ACCESS.match(raw.lstrip("\ufeff"))
    if match:
        fields.update(match.groupdict())
        fields["status"] = int(match["status"])
        if fields["username"] == "-":
            del fields["username"]
    else:
        timestamp = TIMESTAMP.search(raw)
        if timestamp:
            fields["timestamp"] = timestamp[1]
        username = USERNAME.search(raw)
        if username:
            fields["username"] = username[1]
    ips = []
    for candidate in IP_CANDIDATE.finditer(raw):
        try:
            ipaddress.ip_address(candidate[0])
        except ValueError:
            continue
        if candidate[0] not in ips:
            ips.append(candidate[0])
    if ips:
        fields["ip_addresses"] = ips
    return fields


@dataclass(frozen=True, slots=True)
class Evidence:
    line_number: int
    start_char: int
    start_byte: int
    raw: str
    fragment: bool
    continues: bool = False

    @property
    def end_byte(self) -> int:
        return self.start_byte + len(self.raw.encode("utf-8"))

    def slice(self, start: int, end: int) -> "Evidence":
        return Evidence(
            self.line_number, self.start_char + start,
            self.start_byte + len(self.raw[:start].encode("utf-8")),
            self.raw[start:end], True, end < len(self.raw) or self.continues,
        )

    def to_record(self) -> dict:
        return {
            **asdict(self), "end_char": self.start_char + len(self.raw),
            "end_byte": self.end_byte, "fields": extract_fields(self.raw),
        }

    def to_prompt(self) -> dict:
        return {
            "line": self.line_number, "chars": [self.start_char, self.start_char + len(self.raw)],
            "fragment": self.fragment, "raw": self.raw,
        }


def iter_evidence(path: Path) -> Iterator[Evidence]:
    """Read at most two small segments, even for a file containing one giant line.

    Preserve LF, CRLF, CR, BOM, blank lines, final newline, and missing final newline.
    Offsets are half-open; line numbers are 1-based, character/byte offsets 0-based.
    """
    with path.open("r", encoding="utf-8", newline="") as source:
        current = source.readline(READ_CHARS)
        line, char, byte = 1, 0, 0
        while current:
            following = source.readline(READ_CHARS)
            # A bounded read may bisect CRLF. Keep the terminator on its original line.
            if current.endswith("\r") and following.startswith("\n"):
                current += "\n"
                following = following[1:] or source.readline(READ_CHARS)
            ended = current.endswith(("\n", "\r"))
            continues = not ended and bool(following)
            fragment = char > 0 or continues
            evidence = Evidence(line, char, byte, current, fragment, continues)
            yield evidence
            byte = evidence.end_byte
            if ended:
                line, char = line + 1, 0
            else:
                char += len(current)
            current = following
