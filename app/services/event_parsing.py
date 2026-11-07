"""Literal, bounded event extraction. Log statements are observations, not verdicts."""

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from app.services.parsing import ACCESS, extract_fields

AUTH_FAILURE = re.compile(r"\b(?:failed (?:password|login|authentication|auth)|(?:login|authentication|auth) (?:failed|failure)|invalid credentials|authentication failure|(?:auth|login|authentication)[._-](?:failed|failure)|failed_auth)\b", re.I)
AUTH_SUCCESS = re.compile(r"\b(?:accepted (?:password|publickey)|successful (?:login|authentication)|(?:login|authentication) (?:succeeded|successful)|successfully logged in|logged in successfully|(?:auth|login|authentication)[._-](?:success|succeeded))\b", re.I)
SQL_PATTERN = re.compile(r"\bunion\s+(?:all\s+)?select\b|['\"]\s*(?:or|and)\s+['\"\w]+\s*=\s*['\"\w]+|\b(?:sleep|benchmark)\s*\(|;\s*(?:drop|truncate)\s+table\b|\binformation_schema\b", re.I)
SENSITIVE_PATH = re.compile(r"(?:^|/)(?:\.env(?:\.|$|/)|\.git(?:/|$)|wp-admin(?:/|$)|wp-login\.php|phpmyadmin(?:/|$)|phpinfo\.php|etc/passwd|cgi-bin(?:/|$)|actuator(?:/|$)|\.\.(?:/|$))", re.I)
HTTP_REQUEST = re.compile(r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+["\s]+(\d{3})\b')
AUTH_PATH = re.compile(r"/(?:login|signin|sign-in|auth|session|token)(?:/|$)", re.I)
USER = re.compile(r"\b(?:user(?:name)?|account)\s*[=:]\s*['\"]?([\w.@+-]+)|\bfor\s+(?:invalid user\s+|user\s+)?([\w.@+-]+)", re.I)
SOURCE = re.compile(r"\b(?:from|src(?:_ip)?[=:]|source(?:_ip)?[=:]|client(?:_ip)?[=:]|remote(?:_addr)?[=:]|ip[=:])\s*['\"]?\[?([0-9A-Fa-f:.]+)", re.I)
ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def literal_text(value: object, limit: int = 1024) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None  # A JSON-escaped lone surrogate is not usable UTF-8 metadata.
    return value


def parse_timestamp(text: str | None) -> tuple[float | None, str | None]:
    if not text:
        return None, None
    try:
        if re.fullmatch(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}", text):
            date = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        elif ISO.fullmatch(text):
            date = datetime.fromisoformat(text.replace("Z", "+00:00").replace(",", "."))
        else:
            # No year is asserted. This synthetic anchor is used only for relative
            # month/day clock differences; a backward clock starts a new episode.
            date = datetime.strptime("2000 " + text, "%Y %b %d %H:%M:%S")
            return date.replace(tzinfo=timezone.utc).timestamp(), "yearless"
        if date.tzinfo is None:
            return date.replace(tzinfo=timezone.utc).timestamp(), "naive"
        return date.timestamp(), "offset"
    except ValueError:
        return None, None


def source_address(source: str | None) -> str | None:
    if not source:
        return None
    try:
        literal = source.strip("[]")
        with_port = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}", source)
        bracketed = re.fullmatch(r"\[([0-9A-Fa-f:]+)\](?::\d{1,5})?", source)
        if with_port or bracketed:
            literal = (with_port or bracketed)[1]
        return str(ipaddress.ip_address(literal))
    except ValueError:
        return None


def http_status(value: object) -> int | None:
    # Bound conversion before int(): untrusted strings can contain thousands of
    # digits or Unicode characters for which isdigit() does not imply int().
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 100 <= value <= 599 else None
    if isinstance(value, str) and re.fullmatch(r"[1-5][0-9]{2}", value):
        return int(value)
    return None


@dataclass(frozen=True, slots=True)
class ObservedEvent:
    event_type: str
    category: str
    timestamp: str | None
    time_value: float | None
    time_kind: str | None
    source_ip: str | None
    identifier: str | None
    username: str | None
    target: str | None
    request_path: str | None
    http_status: int | None
    excerpt: str
    excerpt_offset: int


def parse_events(raw: str) -> list[ObservedEvent]:
    """Classify explicit auth statements and request payloads, never generic errors."""
    data: dict = {}
    try:
        if raw.lstrip("\ufeff \t").startswith("{"):
            value = json.loads(raw.lstrip("\ufeff"))
            data = value if isinstance(value, dict) else {}
    except (ValueError, RecursionError):
        pass

    def text_value(*keys: str) -> str | None:
        for key in keys:
            value = literal_text(data.get(key))
            if value is not None:
                return value
        return None

    fields = extract_fields(raw)
    access = ACCESS.match(raw.lstrip("\ufeff"))
    leading_iso = ISO.match(raw.lstrip("\ufeff \t["))
    timestamp = text_value("timestamp", "@timestamp", "time", "ts") or (leading_iso[0] if leading_iso else fields.get("timestamp"))
    time_value, time_kind = parse_timestamp(timestamp if isinstance(timestamp, str) else None)
    source_ip = None
    source = text_value("source_ip", "src_ip", "client_ip", "remote_addr", "ip") or fields.get("ip")
    if not source:
        matched = SOURCE.search(raw)
        source = matched[1].rstrip(".") if matched else fields.get("ip")
    if isinstance(source, str):
        source_ip = source_address(source)
    identifier = source_ip or text_value("source_id", "client_id", "device_id", "actor")
    if not identifier and isinstance(fields.get("ip"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fields["ip"]):
        identifier = fields["ip"]  # Observed access-log remote host; never resolve it.
    username = text_value("username", "user", "account")
    if not username:
        if access:
            # Request payload text must not override the access log's remote-user field.
            username = fields.get("username")
        else:
            user = USER.search(raw)
            username = (user[1] or user[2]).rstrip(".,;") if user else fields.get("username")
    if username == "-":
        username = None

    path = text_value("request_path", "path", "url") or fields.get("path")
    status = http_status(data.get("status_code", data.get("status", fields.get("status"))))
    request = HTTP_REQUEST.search(raw)
    if request:
        path, status = path or request[1], status or http_status(request[2])
    if not isinstance(path, str) or len(path) > 4096:
        path = None
    target = None
    if path:
        try:
            target = unquote(unquote(urlsplit(path).path)) or None
        except ValueError:
            pass
    if target is None:
        target = text_value("target", "service")
    if target is None and re.search(r"\bsshd(?:\[|:|\s)", raw):
        # An observed service name is retained, not an invented host or port.
        host = re.match(r"[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+(\S+)\s+sshd", raw)
        target = "sshd@" + host[1] if host else "sshd"

    kinds: list[tuple[str, str, int]] = []
    # Request/agent text is client-controlled. Authentication phrases in an
    # access record do not establish a server authentication outcome.
    auth_text = "" if access else raw
    failed = AUTH_FAILURE.search(auth_text)
    succeeded = AUTH_SUCCESS.search(auth_text)
    if failed:
        kinds.append(("auth_failure", "authentication", failed.start()))
    elif succeeded:
        kinds.append(("auth_success", "authentication", succeeded.start()))
    elif path and AUTH_PATH.search(target or "") and status in {401, 403}:
        kinds.append(("auth_failure", "authentication", raw.find(path)))
    elif status in {401, 403}:
        kinds.append(("unauthorized", "unauthorized", raw.find(path) if path else 0))
    elif re.search(r"\b(?:unauthorized (?:request|access)|access denied|permission denied)\b", raw, re.I):
        kinds.append(("unauthorized", "unauthorized", 0))
    # A 200 response to /login does not prove that authentication succeeded.
    if path is not None:
        decoded = unquote(unquote(path))
        sql = SQL_PATTERN.search(decoded)
        sensitive = SENSITIVE_PATH.search(decoded)
        if sql:
            kinds.append(("sql_injection_pattern", "sql_injection", max(0, raw.find(path))))
        if sensitive:
            kinds.append(("suspicious_path", "scanning", max(0, raw.find(path))))
        if status is not None:
            kinds.append(("http_request", "request_rate", max(0, raw.find(path))))
    # Explicit security-detector messages can supplement non-access-log formats.
    if not any(k[0] == "sql_injection_pattern" for k in kinds) and re.search(r"\bsql injection (?:attempt|detected|blocked)\b", raw, re.I):
        kinds.append(("sql_injection_pattern", "sql_injection", 0))

    events = []
    for event_type, category, position in kinds:
        offset = max(0, position - 80)
        if len(raw) <= 320:
            offset = 0
        excerpt = raw[offset:offset + 320].rstrip("\r\n")
        events.append(ObservedEvent(event_type, category, timestamp, time_value, time_kind,
                                    source_ip, identifier, username, target, path, status, excerpt, offset))
    return events


def supplement_cited_json(raw: str) -> list[ObservedEvent]:
    """AI may point at small custom JSON auth records. Accept only literal facts.

    An operation/outcome pair establishes the logged event; a model's attack label
    does not. The entire source record must fit the bounded quote, so every field
    remains inspectable rather than being hidden outside an extracted excerpt.
    """
    text = raw.rstrip("\r\n")
    if len(text) > 320:
        return []
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    operation = data.get("operation", data.get("action"))
    outcome = data.get("result", data.get("outcome"))
    if not isinstance(operation, str) or not isinstance(outcome, str) or operation not in {"login", "authenticate", "authentication", "signin"}:
        return []
    if outcome in {"failure", "failed", "denied", "invalid_credentials"}:
        kind = "auth_failure"
    elif outcome in {"success", "succeeded", "accepted"}:
        kind = "auth_success"
    else:
        return []

    def literal(*keys: str) -> str | None:
        for key in keys:
            value = literal_text(data.get(key))
            if value is not None:
                return value
        return None

    source = literal("source_ip", "client_ip", "peer_address", "peer_ip", "source_id", "client_id", "device_id")
    address = source_address(source)
    timestamp = literal("timestamp", "time", "ts", "@timestamp")
    clock, basis = parse_timestamp(timestamp)
    return [ObservedEvent(kind, "authentication", timestamp, clock, basis, address, address or source,
                          literal("username", "user", "account"), literal("target", "service"), None, None, text, 0)]
