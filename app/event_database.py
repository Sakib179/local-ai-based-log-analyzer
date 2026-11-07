"""Persistent observations and bounded evidence, independent of model context."""

import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING

from app.config import Settings
from app.services.event_parsing import ObservedEvent, parse_events, supplement_cited_json

if TYPE_CHECKING:
    from app.database import Database

INDEX_VERSION = 1
CORRELATION_TABLES = [
    "incident_ai", "incident_events", "incidents", "correlation_builds", "correlation_state",
    "event_ai", "event_ai_index", "event_chunk_index", "event_links", "event_evidence", "security_events",
]


def migrate_event_schema(connection: sqlite3.Connection) -> None:
    statements = [
        """CREATE TABLE security_events (
            id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
            chunk_id TEXT NOT NULL REFERENCES chunks(id) ON DELETE CASCADE, line INTEGER NOT NULL,
            timestamp TEXT, time_value REAL, time_kind TEXT, source_ip TEXT, identifier TEXT, username TEXT,
            target TEXT, request_path TEXT, http_status INTEGER, event_type TEXT NOT NULL, category TEXT NOT NULL,
            actor_key TEXT NOT NULL, account_key TEXT NOT NULL, target_key TEXT NOT NULL,
            excerpt TEXT NOT NULL, raw_hash TEXT NOT NULL, origin TEXT NOT NULL
        )""",
        """CREATE TABLE event_evidence (
            id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
            chunk_id TEXT NOT NULL REFERENCES chunks(id) ON DELETE CASCADE, line INTEGER NOT NULL,
            start_byte INTEGER NOT NULL, start_char INTEGER NOT NULL, excerpt TEXT NOT NULL
        )""",
        "CREATE TABLE event_links (event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE, evidence_id TEXT NOT NULL REFERENCES event_evidence(id) ON DELETE CASCADE, PRIMARY KEY(event_id,evidence_id))",
        "CREATE TABLE event_ai (event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, line INTEGER NOT NULL, PRIMARY KEY(event_id,finding_id,line))",
        "CREATE TABLE event_ai_index (finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE, version INTEGER NOT NULL)",
        "CREATE TABLE event_chunk_index (chunk_id TEXT PRIMARY KEY REFERENCES chunks(id) ON DELETE CASCADE, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, version INTEGER NOT NULL)",
        """CREATE TABLE correlation_state (
            analysis_id TEXT PRIMARY KEY REFERENCES analyses(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL DEFAULT 0, published_build TEXT
        )""",
        """CREATE TABLE correlation_builds (
            id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL, rules_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'building',
            ignored_ai INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""",
        """CREATE TABLE incidents (
            id TEXT PRIMARY KEY, incident_key TEXT NOT NULL, build_id TEXT NOT NULL REFERENCES correlation_builds(id) ON DELETE CASCADE,
            analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, category TEXT NOT NULL,
            actor_key TEXT NOT NULL, account_key TEXT NOT NULL, target_key TEXT NOT NULL,
            time_kind TEXT, time_start REAL, time_end REAL, timestamp_start TEXT, timestamp_end TEXT,
            start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, published INTEGER NOT NULL DEFAULT 0,
            severity TEXT, title TEXT, reason TEXT, suggested_action TEXT,
            metrics_json TEXT NOT NULL DEFAULT '{}', methods_json TEXT NOT NULL DEFAULT '[]'
        )""",
        "CREATE TABLE incident_events (incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE, PRIMARY KEY(incident_id,event_id))",
        "CREATE TABLE incident_ai (incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, PRIMARY KEY(incident_id,finding_id))",
        "CREATE INDEX event_groups ON security_events(analysis_id,category,actor_key,account_key,target_key,line)",
        "CREATE INDEX event_prior ON security_events(analysis_id,actor_key,line)",
        "CREATE INDEX event_windows ON security_events(analysis_id,category,actor_key,account_key,target_key,event_type,time_kind,time_value,line)",
        "CREATE INDEX event_lines ON event_evidence(analysis_id,line)",
        "CREATE INDEX incident_build ON incidents(build_id,published,category)",
        "CREATE INDEX event_link_evidence ON event_links(evidence_id,event_id)",
    ]
    for statement in statements:
        connection.execute(statement)


def fingerprint(*values: object) -> str:
    return hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def touch_memory(connection: sqlite3.Connection, analysis_id: str) -> None:
    connection.execute("INSERT INTO correlation_state (analysis_id,revision) VALUES (?,1) ON CONFLICT(analysis_id) DO UPDATE SET revision=revision+1", (analysis_id,))


def store_event(connection: sqlite3.Connection, analysis_id: str, chunk_id: str, record: dict,
                event: ObservedEvent, origin: str, finding_id: str | None = None) -> None:
    raw_hash = hashlib.sha256(record["raw"].rstrip("\r\n").encode()).hexdigest()
    actor = "ip:" + event.source_ip if event.source_ip else "id:" + event.identifier if event.identifier else ""
    account = event.username or ""
    target = "*" if event.category in {"scanning", "request_rate"} else event.target or ""
    if event.category == "request_rate":
        account = ""  # A source-level rate spans requested paths/accounts.
    # Identical original records are indistinguishable duplicates. Preserve every
    # original reference but do not turn them into extra failed-login/request counts.
    event_id = fingerprint(analysis_id, event.event_type, actor, account, target, raw_hash,
                           record["line_number"] if record.get("fragment") else None)
    # Reader/model fragments must not count the same normalized event twice at
    # one original line. Partial strings are never deduplicated across other lines.
    existing = connection.execute(
        "SELECT s.id FROM security_events s JOIN event_links l ON l.event_id=s.id JOIN event_evidence e ON e.id=l.evidence_id "
        "WHERE s.analysis_id=? AND s.event_type=? AND e.analysis_id=? AND e.line=? LIMIT 1",
        (analysis_id, event.event_type, analysis_id, record["line_number"]),
    ).fetchone()
    if existing:
        event_id = existing[0]
    connection.execute(
        "INSERT OR IGNORE INTO security_events (id,analysis_id,chunk_id,line,timestamp,time_value,time_kind,source_ip,identifier,username,target,request_path,http_status,event_type,category,actor_key,account_key,target_key,excerpt,raw_hash,origin) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, analysis_id, chunk_id, record["line_number"], event.timestamp, event.time_value, event.time_kind,
         event.source_ip, event.identifier, event.username, event.target, event.request_path, event.http_status,
         event.event_type, event.category, actor, account, target, event.excerpt, raw_hash, origin),
    )
    offset = event.excerpt_offset
    start_byte = record["start_byte"] + len(record["raw"][:offset].encode())
    start_char = record["start_char"] + offset
    evidence_id = fingerprint(analysis_id, record["line_number"], start_byte, event.excerpt)
    connection.execute("INSERT OR IGNORE INTO event_evidence VALUES (?,?,?,?,?,?,?)", (evidence_id, analysis_id, chunk_id, record["line_number"], start_byte, start_char, event.excerpt))
    connection.execute("INSERT OR IGNORE INTO event_links VALUES (?,?)", (event_id, evidence_id))
    if finding_id:
        connection.execute("INSERT OR IGNORE INTO event_ai VALUES (?,?,?)", (event_id, finding_id, record["line_number"]))


def index_chunk_events(connection: sqlite3.Connection, analysis_id: str, chunk_id: str, records: list[dict]) -> None:
    indexed = connection.execute("SELECT version FROM event_chunk_index WHERE chunk_id=?", (chunk_id,)).fetchone()
    if indexed and indexed[0] == INDEX_VERSION:
        return
    for record in records:
        for event in parse_events(record["raw"]):
            store_event(connection, analysis_id, chunk_id, record, event, "deterministic")
    connection.execute("INSERT INTO event_chunk_index VALUES (?,?,?) ON CONFLICT(chunk_id) DO UPDATE SET version=excluded.version", (chunk_id, analysis_id, INDEX_VERSION))
    touch_memory(connection, analysis_id)


def index_ai_events(connection: sqlite3.Connection, unit: dict, finding_id: str, finding: dict) -> None:
    if connection.execute("SELECT 1 FROM event_ai_index WHERE finding_id=? AND version=?", (finding_id, INDEX_VERSION)).fetchone():
        return
    for citation in finding["evidence"]:
        for record in unit["entries"]:
            if record["line_number"] != citation["line"] or citation["excerpt"] not in record["raw"]:
                continue
            # A validated suspicion is not itself an observed authentication/SQL
            # event. Only literal facts recognizable in its original evidence count.
            parsed = parse_events(record["raw"])
            if not any(event.category == "authentication" for event in parsed):
                parsed += supplement_cited_json(record["raw"])
            for event in parsed:
                store_event(connection, unit["analysis_id"], unit["chunk_id"], record, event, "ai_supported", finding_id)
    connection.execute("INSERT INTO event_ai_index VALUES (?,?) ON CONFLICT(finding_id) DO UPDATE SET version=excluded.version", (finding_id, INDEX_VERSION))
    touch_memory(connection, unit["analysis_id"])


class EventStore:
    def __init__(self, database: "Database", settings: Settings | None = None) -> None:
        self.database = database
        self.settings = settings or Settings()

    def _context_window(self, clock: float | None, kind: str | None, before: int, prefix: str = "") -> tuple[str, list]:
        if clock is None:
            return f" AND {prefix}line>=?", [before - self.settings.correlation_line_window]
        conditions = []
        arguments: list = [kind, clock]
        for category, window in [
            ("authentication", self.settings.auth_window_seconds), ("sql_injection", self.settings.sql_window_seconds),
            ("scanning", self.settings.scan_window_seconds), ("unauthorized", self.settings.unauthorized_window_seconds),
        ]:
            conditions.append(f"({prefix}category=? AND {prefix}time_value>=?)")
            arguments.extend([category, clock - window])
        return f" AND {prefix}time_kind=? AND {prefix}time_value<=? AND (" + " OR ".join(conditions) + ")", arguments

    def ensure_indexed(self, analysis_id: str) -> None:
        """Backfill legacy jobs one bounded prepared chunk/finding at a time."""
        while True:
            with self.database.connection() as connection:
                row = connection.execute(
                    "SELECT c.id,c.entries_json FROM chunks c LEFT JOIN event_chunk_index i ON i.chunk_id=c.id "
                    "WHERE c.analysis_id=? AND (i.version IS NULL OR i.version!=?) ORDER BY c.ordinal LIMIT 1",
                    (analysis_id, INDEX_VERSION),
                ).fetchone()
                if row is None:
                    break
                index_chunk_events(connection, analysis_id, row["id"], json.loads(row["entries_json"]))
        while True:
            with self.database.connection() as connection:
                row = connection.execute(
                    "SELECT f.id,f.chunk_id,f.finding_json,u.entries_json FROM findings f JOIN inference_units u ON u.id=f.unit_id "
                    "LEFT JOIN event_ai_index i ON i.finding_id=f.id WHERE f.analysis_id=? AND (i.version IS NULL OR i.version!=?) LIMIT 1",
                    (analysis_id, INDEX_VERSION),
                ).fetchone()
                if row is None:
                    break
                index_ai_events(connection, {"analysis_id": analysis_id, "chunk_id": row["chunk_id"], "entries": json.loads(row["entries_json"])}, row["id"], json.loads(row["finding_json"]))

    def compact_context(self, analysis_id: str, entries: list) -> str:
        """Only relevant prior records; no future evidence or full-history prompt."""
        if not entries:
            return ""
        before = min(entry.line_number for entry in entries)
        actors: list[tuple] = []
        for entry in entries:
            for event in parse_events(entry.raw) or supplement_cited_json(entry.raw):
                actor = "ip:" + event.source_ip if event.source_ip else "id:" + event.identifier if event.identifier else ""
                scope = (actor, event.username, event.target)
                if actor and not any(previous[:3] == scope for previous in actors):
                    actors.append((*scope, event.time_value, event.time_kind))
                if len(actors) == 3:
                    break
            if len(actors) == 3:
                break
        summaries = []
        with self.database.connection() as connection:
            for actor, account, target, clock, kind in actors:
                scope_query = ""
                arguments: list = [analysis_id, actor, before]
                time_query, time_arguments = self._context_window(clock, kind, before)
                scope_query += time_query
                arguments += time_arguments
                if account:
                    scope_query += " AND account_key=?"
                    arguments.append(account)
                if target:
                    scope_query += " AND target_key IN (?, '*')"
                    arguments.append(target)
                rows = connection.execute(
                    "SELECT account_key,target_key,COUNT(DISTINCT CASE WHEN event_type='auth_failure' THEN id END) AS failures, "
                    "COUNT(DISTINCT CASE WHEN event_type='auth_success' THEN id END) AS successes, "
                    "SUM(event_type='sql_injection_pattern') AS sql_attempts,SUM(event_type='suspicious_path') AS sensitive_paths, "
                    "SUM(event_type='unauthorized') AS denied,MIN(line) AS first_line,MAX(line) AS last_line "
                    "FROM security_events WHERE analysis_id=? AND actor_key=? AND line<? AND category IN ('authentication','sql_injection','scanning','unauthorized') "
                    + scope_query + " GROUP BY account_key,target_key ORDER BY failures DESC,COUNT(*) DESC LIMIT 2", arguments,
                )
                for row in rows:
                    ai_time_query, ai_time_arguments = self._context_window(clock, kind, before, "e.")
                    ai_filter = " WHERE e.analysis_id=? AND e.actor_key=? AND e.line<? AND a.line<? AND e.account_key=? AND e.target_key=?" + ai_time_query
                    ai_arguments = [analysis_id, actor, before, before, row["account_key"], row["target_key"], *ai_time_arguments]
                    ai_count = connection.execute(
                        "SELECT COUNT(DISTINCT a.finding_id) FROM event_ai a JOIN security_events e ON e.id=a.event_id" + ai_filter,
                        ai_arguments,
                    ).fetchone()[0]
                    summary = {"source": actor[3:], "account": row["account_key"] or None, "target": row["target_key"] or None,
                               "failed": row["failures"], "successful": row["successes"], "sql_attempts": row["sql_attempts"],
                               "sensitive_paths": row["sensitive_paths"], "denied": row["denied"],
                               "first_line": row["first_line"], "last_line": row["last_line"], "prior_ai_suspicions": ai_count,
                               "time_basis": kind or "line_order_only"}
                    previous_ai = connection.execute(
                        "SELECT DISTINCT f.finding_json,f.created_at FROM event_ai a JOIN security_events e ON e.id=a.event_id JOIN findings f ON f.id=a.finding_id"
                        + ai_filter + " ORDER BY f.created_at DESC LIMIT 1", ai_arguments,
                    ).fetchone()
                    if previous_ai:
                        finding = json.loads(previous_ai["finding_json"])
                        summary["prior_ai_assessment"] = {"label": finding["attack_type"], "severity": finding["severity"], "confidence": "possible"}
                    candidate = json.dumps({"prior_observations": summaries + [summary]}, separators=(",", ":"))
                    if len(candidate) > 512 and "prior_ai_assessment" in summary:
                        del summary["prior_ai_assessment"]
                        candidate = json.dumps({"prior_observations": summaries + [summary]}, separators=(",", ":"))
                    if len(candidate) <= 512:
                        summaries.append(summary)
        return json.dumps({"prior_observations": summaries}, separators=(",", ":")) if summaries else ""
