"""Transactional Phase 3 checkpoints, attempts, and evidence-verified candidates."""

import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING
from uuid import uuid4

from app.errors import AppError
from app.event_database import index_ai_events

if TYPE_CHECKING:
    from app.database import Database

NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"


def migrate_inference_schema(connection: sqlite3.Connection) -> None:
    statements = [
        """CREATE TABLE inference_runs (
            analysis_id TEXT PRIMARY KEY REFERENCES analyses(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK(status IN ('queued','running','completed','partially_completed','failed')),
            config_json TEXT NOT NULL, error_code TEXT, error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""",
        """CREATE TABLE inference_chunks (
            chunk_id TEXT PRIMARY KEY REFERENCES chunks(id) ON DELETE CASCADE,
            analysis_id TEXT NOT NULL REFERENCES inference_runs(analysis_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL, planned INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
            error_code TEXT, error_message TEXT,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""",
        """CREATE TABLE inference_units (
            id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES inference_runs(analysis_id) ON DELETE CASCADE,
            chunk_id TEXT NOT NULL REFERENCES inference_chunks(chunk_id) ON DELETE CASCADE,
            parent_id TEXT REFERENCES inference_units(id) ON DELETE CASCADE,
            position TEXT NOT NULL, entries_json TEXT NOT NULL, payload_json TEXT NOT NULL,
            input_tokens INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','splitting','superseded')),
            attempts INTEGER NOT NULL DEFAULT 0, round_attempts INTEGER NOT NULL DEFAULT 0,
            duration_ms REAL NOT NULL DEFAULT 0, error_code TEXT, error_message TEXT,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(chunk_id, position)
        )""",
        """CREATE TABLE inference_attempts (
            id INTEGER PRIMARY KEY, unit_id TEXT NOT NULL REFERENCES inference_units(id) ON DELETE CASCADE,
            attempt INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'running', input_tokens INTEGER,
            duration_ms REAL NOT NULL DEFAULT 0, diagnostics_json TEXT NOT NULL DEFAULT '{}',
            error_code TEXT, error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(unit_id, attempt)
        )""",
        """CREATE TABLE findings (
            id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES inference_runs(analysis_id) ON DELETE CASCADE,
            chunk_id TEXT NOT NULL REFERENCES inference_chunks(chunk_id) ON DELETE CASCADE,
            unit_id TEXT NOT NULL REFERENCES inference_units(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL, finding_json TEXT NOT NULL,
            validation_status TEXT NOT NULL DEFAULT 'evidence_verified',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(unit_id, fingerprint)
        )""",
        "CREATE INDEX inference_queue ON inference_runs(status, updated_at)",
        "CREATE INDEX inference_unit_order ON inference_units(chunk_id, status, position)",
        "CREATE INDEX findings_analysis ON findings(analysis_id, chunk_id)",
    ]
    for statement in statements:
        connection.execute(statement)


class InferenceStore:
    def __init__(self, database: "Database") -> None:
        self.database = database

    def queue(self, analysis_id: str, config: dict) -> str:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            analysis = connection.execute("SELECT status,total_chunks FROM analyses WHERE id=?", (analysis_id,)).fetchone()
            if analysis is None:
                raise AppError(404, "analysis_not_found", "Analysis not found.")
            if analysis["status"] != "ready" or not analysis["total_chunks"]:
                raise AppError(409, "analysis_not_ready", "Log preparation must be ready before starting inference.")
            run = connection.execute("SELECT status FROM inference_runs WHERE analysis_id=?", (analysis_id,)).fetchone()
            if run is not None and run["status"] in {"queued", "running", "completed"}:
                return run["status"]
            if run is None:
                connection.execute(
                    "INSERT INTO inference_runs (analysis_id,status,config_json) VALUES (?,'queued',?)",
                    (analysis_id, json.dumps(config, ensure_ascii=False)),
                )
                connection.execute(
                    "INSERT INTO inference_chunks (chunk_id,analysis_id,ordinal) SELECT id,analysis_id,ordinal FROM chunks WHERE analysis_id=?",
                    (analysis_id,),
                )
            else:
                connection.execute(
                    f"UPDATE inference_runs SET status='queued',error_code=NULL,error_message=NULL,updated_at={NOW} WHERE analysis_id=?",
                    (analysis_id,),
                )
                connection.execute("DELETE FROM inference_units WHERE parent_id IN (SELECT id FROM inference_units WHERE analysis_id=? AND status='splitting')", (analysis_id,))
                connection.execute(
                    "UPDATE inference_units SET status='pending',round_attempts=0,error_code=NULL,error_message=NULL "
                    "WHERE analysis_id=? AND status IN ('failed','pending','running','splitting')", (analysis_id,),
                )
                connection.execute(
                    "UPDATE inference_chunks SET status='pending',error_code=NULL,error_message=NULL WHERE analysis_id=? AND status!='completed'",
                    (analysis_id,),
                )
            return "queued"

    def recover(self) -> bool:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            uncertain = connection.execute("SELECT 1 FROM inference_attempts WHERE status='running' LIMIT 1").fetchone() is not None
            row = connection.execute("SELECT value FROM app_metadata WHERE key='inference_uncertain'").fetchone()
            uncertain = uncertain or (row is not None and row[0] == "1")
            connection.execute("UPDATE inference_attempts SET status='failed',error_code='interrupted',error_message='Inference interrupted before checkpoint.' WHERE status='running'")
            connection.execute("DELETE FROM inference_units WHERE parent_id IN (SELECT id FROM inference_units WHERE status='splitting')")
            connection.execute("UPDATE inference_units SET status='pending' WHERE status IN ('running','splitting')")
            # Incomplete planning has never started inference; discard only that plan.
            connection.execute("DELETE FROM inference_units WHERE chunk_id IN (SELECT chunk_id FROM inference_chunks WHERE planned=0)")
            connection.execute("UPDATE inference_chunks SET status='pending' WHERE status='running'")
            connection.execute(f"UPDATE inference_runs SET status='queued',updated_at={NOW} WHERE status='running'")
            return uncertain

    def claim(self) -> dict | None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM inference_runs WHERE status='queued' ORDER BY updated_at,analysis_id LIMIT 1").fetchone()
            if row is None:
                return None
            connection.execute(f"UPDATE inference_runs SET status='running',updated_at={NOW} WHERE analysis_id=?", (row["analysis_id"],))
            return {**dict(row), "config": json.loads(row["config_json"])}

    def next_chunk(self, analysis_id: str) -> dict | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM inference_chunks WHERE analysis_id=? AND status IN ('pending','running') ORDER BY ordinal LIMIT 1",
                (analysis_id,),
            ).fetchone()
            if row is None:
                return None
            connection.execute("UPDATE inference_chunks SET status='running' WHERE chunk_id=?", (row["chunk_id"],))
            return dict(row)

    def save_unit(self, analysis_id: str, chunk_id: str, position: str, entries: list[dict],
                  payload: dict, tokens: int, parent_id: str | None = None) -> None:
        with self.database.connection() as connection:
            connection.execute(
                "INSERT INTO inference_units (id,analysis_id,chunk_id,parent_id,position,entries_json,payload_json,input_tokens) VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid4()), analysis_id, chunk_id, parent_id, position, json.dumps(entries, ensure_ascii=False), json.dumps(payload, ensure_ascii=False), tokens),
            )

    def finish_plan(self, chunk_id: str) -> None:
        with self.database.connection() as connection:
            connection.execute("UPDATE inference_chunks SET planned=1 WHERE chunk_id=?", (chunk_id,))

    def clear_unfinished_plan(self, chunk_id: str) -> None:
        with self.database.connection() as connection:
            connection.execute("DELETE FROM inference_units WHERE chunk_id=? AND EXISTS (SELECT 1 FROM inference_chunks WHERE chunk_id=? AND planned=0)", (chunk_id, chunk_id))

    def next_unit(self, chunk_id: str) -> dict | None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM inference_units WHERE chunk_id=? AND status='pending' ORDER BY position LIMIT 1", (chunk_id,)).fetchone()
            if row is None:
                return None
            return {**dict(row), "entries": json.loads(row["entries_json"]), "payload": json.loads(row["payload_json"])}

    def begin_split(self, unit_id: str) -> None:
        with self.database.connection() as connection:
            connection.execute("UPDATE inference_units SET status='splitting' WHERE id=?", (unit_id,))

    def finish_split(self, unit_id: str) -> None:
        with self.database.connection() as connection:
            connection.execute("UPDATE inference_units SET status='superseded' WHERE id=?", (unit_id,))

    def abort_split(self, unit_id: str) -> None:
        with self.database.connection() as connection:
            connection.execute("DELETE FROM inference_units WHERE parent_id=?", (unit_id,))

    def begin_attempt(self, unit_id: str, payload: dict) -> int:
        with self.database.connection() as connection:
            connection.execute(
                f"UPDATE inference_units SET status='running',attempts=attempts+1,round_attempts=round_attempts+1,payload_json=?,updated_at={NOW} WHERE id=?",
                (json.dumps(payload, ensure_ascii=False), unit_id),
            )
            number = connection.execute("SELECT attempts FROM inference_units WHERE id=?", (unit_id,)).fetchone()[0]
            cursor = connection.execute("INSERT INTO inference_attempts (unit_id,attempt) VALUES (?,?)", (unit_id, number))
            return int(cursor.lastrowid)

    def finish_attempt(self, attempt_id: int, duration_ms: float, diagnostics: dict, code: str | None,
                       message: str | None, uncertain: bool) -> None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT unit_id FROM inference_attempts WHERE id=?", (attempt_id,)).fetchone()
            connection.execute(
                "UPDATE inference_attempts SET status=?,duration_ms=?,diagnostics_json=?,input_tokens=?,error_code=?,error_message=? WHERE id=?",
                ("failed" if code else "completed", duration_ms, json.dumps(diagnostics), diagnostics.get("input_tokens"), code, message, attempt_id),
            )
            connection.execute("UPDATE inference_units SET duration_ms=duration_ms+?,input_tokens=COALESCE(?,input_tokens) WHERE id=?", (duration_ms, diagnostics.get("input_tokens"), row[0]))
            connection.execute("INSERT INTO app_metadata (key,value) VALUES ('inference_uncertain',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("1" if uncertain else "0",))

    def complete_unit(self, unit: dict, findings: list[dict]) -> None:
        with self.database.connection() as connection:
            for finding in findings:
                raw = json.dumps(finding, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                connection.execute(
                    "INSERT OR IGNORE INTO findings (id,analysis_id,chunk_id,unit_id,fingerprint,finding_json) VALUES (?,?,?,?,?,?)",
                    (str(uuid4()), unit["analysis_id"], unit["chunk_id"], unit["id"], hashlib.sha256(raw.encode()).hexdigest(), raw),
                )
                finding_id = connection.execute("SELECT id FROM findings WHERE unit_id=? AND fingerprint=?", (unit["id"], hashlib.sha256(raw.encode()).hexdigest())).fetchone()[0]
                index_ai_events(connection, unit, finding_id, finding)
            connection.execute(f"UPDATE inference_units SET status='completed',error_code=NULL,error_message=NULL,updated_at={NOW} WHERE id=?", (unit["id"],))
            connection.execute(f"UPDATE inference_runs SET updated_at={NOW} WHERE analysis_id=?", (unit["analysis_id"],))

    def fail_unit(self, unit_id: str, code: str, message: str) -> None:
        with self.database.connection() as connection:
            connection.execute(f"UPDATE inference_units SET status='failed',error_code=?,error_message=?,updated_at={NOW} WHERE id=?", (code, message, unit_id))

    def finish_chunk(self, chunk_id: str, code: str | None = None, message: str | None = None) -> None:
        with self.database.connection() as connection:
            bad = connection.execute("SELECT error_code,error_message FROM inference_units WHERE chunk_id=? AND status='failed' ORDER BY position LIMIT 1", (chunk_id,)).fetchone()
            if bad and code is None:
                code, message = bad[0], bad[1]
            connection.execute(f"UPDATE inference_chunks SET status=?,error_code=?,error_message=?,updated_at={NOW} WHERE chunk_id=?", ("failed" if code else "completed", code, message, chunk_id))
            connection.execute(f"UPDATE inference_runs SET updated_at={NOW} WHERE analysis_id=(SELECT analysis_id FROM inference_chunks WHERE chunk_id=?)", (chunk_id,))

    def finish_run(self, analysis_id: str, code: str | None = None, message: str | None = None) -> None:
        progress = self.progress(analysis_id)
        assert progress is not None
        if progress["completed_chunks"] == progress["total_chunks"] and not code:
            status = "completed"
        elif progress["completed_units"]:
            status = "partially_completed"
        else:
            status = "failed"
        with self.database.connection() as connection:
            if status != "completed" and code is None:
                error = connection.execute("SELECT error_code,error_message FROM inference_chunks WHERE analysis_id=? AND status='failed' ORDER BY ordinal LIMIT 1", (analysis_id,)).fetchone()
                code, message = (error[0], error[1]) if error else ("inference_incomplete", "Some chunks were not completed.")
            connection.execute(f"UPDATE inference_runs SET status=?,error_code=?,error_message=?,updated_at={NOW} WHERE analysis_id=?", (status, code, message, analysis_id))

    def progress(self, analysis_id: str) -> dict | None:
        with self.database.connection() as connection:
            run = connection.execute("SELECT status,error_code,error_message,created_at,updated_at FROM inference_runs WHERE analysis_id=?", (analysis_id,)).fetchone()
            if run is None:
                return None
            chunks = connection.execute("SELECT COUNT(*),COALESCE(SUM(status='completed'),0),COALESCE(SUM(status='failed'),0) FROM inference_chunks WHERE analysis_id=?", (analysis_id,)).fetchone()
            units = connection.execute("SELECT COALESCE(SUM(status='completed'),0),COALESCE(SUM(status='failed'),0),COALESCE(SUM(attempts),0),COALESCE(SUM(MAX(attempts-1,0)),0) FROM inference_units WHERE analysis_id=?", (analysis_id,)).fetchone()
            count = connection.execute("SELECT COUNT(*) FROM findings WHERE analysis_id=?", (analysis_id,)).fetchone()[0]
            current = connection.execute("SELECT ordinal FROM inference_chunks WHERE analysis_id=? AND status='running' ORDER BY ordinal LIMIT 1", (analysis_id,)).fetchone()
            return {"status": run["status"], "error": {"code": run["error_code"], "message": run["error_message"]} if run["error_code"] else None,
                    "created_at": run["created_at"], "updated_at": run["updated_at"], "total_chunks": chunks[0], "completed_chunks": chunks[1], "failed_chunks": chunks[2],
                    "completed_units": units[0], "failed_units": units[1], "attempts": units[2], "retries": units[3], "findings_count": count,
                    "current_chunk": current[0] if current and run["status"] == "running" else None}

    def chunk_progress(self, chunk_id: str) -> dict | None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT status,error_code,error_message FROM inference_chunks WHERE chunk_id=?", (chunk_id,)).fetchone()
            if row is None:
                return None
            units = connection.execute("SELECT COUNT(*),COALESCE(SUM(status='completed'),0),COALESCE(SUM(attempts),0),COALESCE(SUM(duration_ms),0),COALESCE(SUM(input_tokens),0) FROM inference_units WHERE chunk_id=? AND status!='superseded'", (chunk_id,)).fetchone()
            totals = connection.execute("SELECT COALESCE(SUM(attempts),0),COALESCE(SUM(duration_ms),0),COALESCE(SUM(MAX(attempts-1,0)),0) FROM inference_units WHERE chunk_id=?", (chunk_id,)).fetchone()
            return {**dict(row), "total_units": units[0], "completed_units": units[1], "attempts": totals[0], "retries": totals[2], "duration_ms": totals[1], "input_tokens": units[4]}

    def list_findings(self, analysis_id: str, limit: int, offset: int) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute("SELECT f.* FROM findings f JOIN chunks c ON c.id=f.chunk_id JOIN inference_units u ON u.id=f.unit_id WHERE f.analysis_id=? ORDER BY c.ordinal,u.position,f.id LIMIT ? OFFSET ?", (analysis_id, limit, offset))
            return [{**{k: row[k] for k in row.keys() if k != "finding_json"}, "finding": json.loads(row["finding_json"])} for row in rows]

    def list_attempts(self, analysis_id: str, limit: int, offset: int) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute("SELECT a.*,u.chunk_id FROM inference_attempts a JOIN inference_units u ON u.id=a.unit_id WHERE u.analysis_id=? ORDER BY a.id LIMIT ? OFFSET ?", (analysis_id, limit, offset))
            return [{**{k: row[k] for k in row.keys() if k != "diagnostics_json"}, "diagnostics": json.loads(row["diagnostics_json"])} for row in rows]
