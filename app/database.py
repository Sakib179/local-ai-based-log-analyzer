"""Small SQLite access layer with short-lived, transaction-scoped connections."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.inference_database import migrate_inference_schema
from app.event_database import index_chunk_events, migrate_event_schema, touch_memory

SCHEMA_VERSION = "4"


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connection(self, *, cross_thread: bool = False) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on failure, and always close the connection."""
        connection = sqlite3.connect(self.path, timeout=5.0, check_same_thread=not cross_thread)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS app_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO app_metadata (key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            row = connection.execute(
                "SELECT value FROM app_metadata WHERE key = ?", ("schema_version",)
            ).fetchone()
            if row is None or row["value"] not in {"1", "2", "3", SCHEMA_VERSION}:
                raise RuntimeError("Unsupported database schema version; migration required.")
            if row["value"] == "1":
                connection.execute("""
                    CREATE TABLE analyses (
                        id TEXT PRIMARY KEY,
                        filename TEXT NOT NULL DEFAULT '',
                        source_path TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        sha256 TEXT,
                        encoding TEXT NOT NULL DEFAULT 'utf-8',
                        status TEXT NOT NULL CHECK(status IN ('uploading','queued','processing','ready','failed')),
                        total_lines INTEGER NOT NULL DEFAULT 0,
                        total_chunks INTEGER NOT NULL DEFAULT 0,
                        preparation_config TEXT NOT NULL,
                        error_code TEXT,
                        error_message TEXT,
                        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                    )
                """)
                connection.execute("""
                    CREATE TABLE chunks (
                        id TEXT PRIMARY KEY,
                        analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        start_line INTEGER NOT NULL,
                        end_line INTEGER NOT NULL,
                        start_byte INTEGER NOT NULL,
                        end_byte INTEGER NOT NULL,
                        input_tokens INTEGER NOT NULL CHECK(input_tokens >= 0),
                        status TEXT NOT NULL CHECK(status IN ('prepared','failed')),
                        entries_json TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                        UNIQUE(analysis_id, ordinal)
                    )
                """)
                connection.execute("CREATE INDEX analyses_queue ON analyses(status, created_at)")
                connection.execute(
                    "UPDATE app_metadata SET value = '2' WHERE key = 'schema_version'"
                )
            if row["value"] in {"1", "2"}:
                migrate_inference_schema(connection)
            if row["value"] in {"1", "2", "3"}:
                migrate_event_schema(connection)
                connection.execute("UPDATE app_metadata SET value = ? WHERE key='schema_version'", (SCHEMA_VERSION,))

    def get_metadata(self, key: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT value FROM app_metadata WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row is not None else None

    def set_metadata(self, key: str, value: str) -> None:
        if key == "schema_version":
            raise ValueError("Schema version is managed by database initialization.")
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def is_healthy(self) -> bool:
        return self.get_metadata("schema_version") == SCHEMA_VERSION

    def create_analysis(self, analysis_id: str, source_path: Path, preparation_config: dict) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO analyses (id, source_path, status, preparation_config) VALUES (?,?,'uploading',?)",
                (analysis_id, str(source_path), json.dumps(preparation_config, ensure_ascii=False)),
            )

    def queue_analysis(self, analysis_id: str, filename: str, size_bytes: int, sha256: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET filename=?, size_bytes=?, sha256=?, status='queued', "
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status='uploading'",
                (filename, size_bytes, sha256, analysis_id),
            )

    def get_analysis(self, analysis_id: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
            return dict(row) if row is not None else None

    def recover_interrupted(self) -> None:
        """One-worker deployment: requeue preparation; fail incomplete uploads."""
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in connection.execute("SELECT id FROM analyses WHERE status='processing'"):
                touch_memory(connection, row[0])
            connection.execute(
                "DELETE FROM chunks WHERE analysis_id IN (SELECT id FROM analyses WHERE status='processing')"
            )
            connection.execute(
                "UPDATE analyses SET status='queued', total_chunks=0, total_lines=0, "
                "error_code=NULL, error_message=NULL, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE status='processing'"
            )
            connection.execute(
                "UPDATE analyses SET status='failed', error_code='upload_interrupted', "
                "error_message='Upload interrupted before validation completed.', "
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE status='uploading'"
            )

    def claim_analysis(self) -> dict | None:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM analyses WHERE status='queued' ORDER BY created_at, id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE analyses SET status='processing', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                (row["id"],),
            )
            return {**dict(row), "status": "processing"}

    def save_chunk(self, analysis_id: str, chunk_id: str, ordinal: int, entries: list[dict],
                   payload: dict, input_tokens: int) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO chunks (id,analysis_id,ordinal,start_line,end_line,start_byte,end_byte,"
                "input_tokens,status,entries_json,payload_json) VALUES (?,?,?,?,?,?,?,?,'prepared',?,?)",
                (chunk_id, analysis_id, ordinal, entries[0]["line_number"], entries[-1]["line_number"],
                 entries[0]["start_byte"], entries[-1]["end_byte"], input_tokens,
                 json.dumps(entries, ensure_ascii=False), json.dumps(payload, ensure_ascii=False)),
            )
            connection.execute(
                "UPDATE analyses SET total_chunks=?, total_lines=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                (ordinal, entries[-1]["line_number"], analysis_id),
            )
            index_chunk_events(connection, analysis_id, chunk_id, entries)

    def finish_analysis(self, analysis_id: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET status='ready', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                (analysis_id,),
            )

    def fail_analysis(self, analysis_id: str, code: str, message: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE analyses SET status='failed', error_code=?, error_message=?, "
                "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                (code, message, analysis_id),
            )
            connection.execute("UPDATE chunks SET status='failed' WHERE analysis_id=?", (analysis_id,))

    def list_chunks(self, analysis_id: str, limit: int = 20, offset: int = 0) -> list[dict]:
        with self.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT id,analysis_id,ordinal,start_line,end_line,start_byte,end_byte,input_tokens,status,created_at "
                "FROM chunks WHERE analysis_id=? ORDER BY ordinal LIMIT ? OFFSET ?",
                (analysis_id, limit, offset),
            )]

    def get_chunk(self, analysis_id: str, chunk_id: str) -> dict | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM chunks WHERE analysis_id=? AND id=?", (analysis_id, chunk_id)
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["entries"] = json.loads(result.pop("entries_json"))
            result["payload"] = json.loads(result.pop("payload_json"))
            return result
