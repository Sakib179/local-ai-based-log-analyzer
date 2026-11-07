import sqlite3
from pathlib import Path

import pytest

from app.database import Database
from app.event_database import CORRELATION_TABLES
from app.services.parsing import Evidence
from app.services.prompts import PromptBuilder


def test_initialization_is_idempotent_and_values_persist(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "analyzer.sqlite3"
    database = Database(path)
    database.initialize()
    database.set_metadata("example", "first")
    database.initialize()
    assert database.is_healthy()
    assert Database(path).get_metadata("example") == "first"
    database.set_metadata("example", "second")
    assert Database(path).get_metadata("example") == "second"
    assert database.get_metadata("missing") is None
    with database.connection() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_failed_transaction_rolls_back_and_connection_closes(tmp_path: Path) -> None:
    database = Database(tmp_path / "analyzer.sqlite3")
    database.initialize()
    with pytest.raises(RuntimeError, match="abort"):
        with database.connection() as connection:
            connection.execute("INSERT INTO app_metadata VALUES (?, ?)", ("temporary", "value"))
            raise RuntimeError("abort")
    assert database.get_metadata("temporary") is None
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_metadata_queries_treat_input_as_data(tmp_path: Path) -> None:
    database = Database(tmp_path / "analyzer.sqlite3")
    database.initialize()
    key = "'; DROP TABLE app_metadata; --"
    database.set_metadata(key, "a value containing 'quotes'")
    assert database.get_metadata(key) == "a value containing 'quotes'"
    assert database.is_healthy()


def test_unknown_schema_is_rejected_without_overwriting_it(tmp_path: Path) -> None:
    database = Database(tmp_path / "analyzer.sqlite3")
    database.initialize()
    with pytest.raises(ValueError, match="Schema version"):
        database.set_metadata("schema_version", "2")
    with database.connection() as connection:
        connection.execute("UPDATE app_metadata SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(RuntimeError, match="migration required"):
        database.initialize()
    assert database.get_metadata("schema_version") == "99"


def test_phase_one_database_migrates_without_losing_metadata(tmp_path: Path) -> None:
    path = tmp_path / "existing.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.executemany("INSERT INTO app_metadata VALUES (?,?)", [("schema_version", "1"), ("keep", "original")])
    database = Database(path)
    database.initialize()
    database.initialize()
    assert database.get_metadata("schema_version") == "4"
    assert database.get_metadata("keep") == "original"
    with database.connection() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"app_metadata", "analyses", "chunks"} <= tables


def test_phase_two_migration_preserves_prepared_jobs_and_chunks(tmp_path: Path) -> None:
    database = Database(tmp_path / "phase-two.sqlite3")
    database.initialize()
    database.create_analysis("existing-job", tmp_path / "original.log", {"context_tokens": 2048, "prompt": {}})
    database.queue_analysis("existing-job", "original.log", 6, "digest")
    evidence = Evidence(1, 0, 0, "hello\n", False)
    database.save_chunk("existing-job", "existing-chunk", 1, [evidence.to_record()], PromptBuilder().build([evidence]), 100)
    database.finish_analysis("existing-job")
    before_job = database.get_analysis("existing-job")
    before_chunk = database.get_chunk("existing-job", "existing-chunk")
    # Reconstruct v2 only after seeding its prepared rows.
    with database.connection() as connection:
        for table in CORRELATION_TABLES + ["findings", "inference_attempts", "inference_units", "inference_chunks", "inference_runs"]:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("UPDATE app_metadata SET value='2' WHERE key='schema_version'")
    database.initialize()
    assert database.get_metadata("schema_version") == "4"
    assert database.get_analysis("existing-job") == before_job
    assert database.get_chunk("existing-job", "existing-chunk") == before_chunk
