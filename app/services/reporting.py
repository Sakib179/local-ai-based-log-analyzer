"""Snapshot-consistent JSON reports streamed without collecting all evidence in RAM."""

import json
from collections.abc import Iterator

from app.config import Settings
from app.database import Database
from app.inference_database import InferenceStore
from app.services.correlation import Correlator

SEVERITIES = ("Low", "Medium", "High", "Critical")


def encode(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class ReportService:
    def __init__(self, database: Database, inference: InferenceStore, correlator: Correlator, settings: Settings) -> None:
        self.database, self.inference, self.correlator, self.settings = database, inference, correlator, settings

    def prepare(self, analysis_id: str) -> None:
        self.correlator.refresh(analysis_id)

    def stream(self, analysis_id: str) -> Iterator[str]:
        # StreamingResponse advances a sync generator sequentially, but may use a
        # different worker thread for each next(). This connection is never used
        # concurrently and owns one read-only snapshot for the whole response.
        with self.database.connection(cross_thread=True) as connection:
            connection.execute("BEGIN")
            job = connection.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
            state = connection.execute("SELECT * FROM correlation_state WHERE analysis_id=?", (analysis_id,)).fetchone()
            build = connection.execute("SELECT * FROM correlation_builds WHERE id=?", (state["published_build"],)).fetchone()
            build_id = build["id"]
            run = connection.execute("SELECT status,error_code,error_message FROM inference_runs WHERE analysis_id=?", (analysis_id,)).fetchone()
            status = run["status"] if run else job["status"]
            indexed_chunks = connection.execute("SELECT COUNT(*) FROM event_chunk_index WHERE analysis_id=?", (analysis_id,)).fetchone()[0]
            processed = connection.execute("SELECT COUNT(*) FROM inference_chunks WHERE analysis_id=? AND status='completed'", (analysis_id,)).fetchone()[0]
            severity_counts = dict.fromkeys(SEVERITIES, 0)
            for row in connection.execute("SELECT severity,COUNT(*) FROM incidents WHERE build_id=? AND published=1 GROUP BY severity", (build_id,)):
                severity_counts[row[0]] = row[1]
            limitations = [
                "Confirmed log observations are separated from possible security risks; successful authentication does not confirm account compromise.",
                "Field extraction is best-effort. Very long fragmented entries or unsupported formats may hide event fields.",
                "Identical records are counted once; every original reference is retained. Repeated identical requests without unique log fields may be undercounted.",
                "Thresholds and a small local model can miss attacks or flag legitimate behavior; no automatic remediation is performed.",
            ]
            if connection.execute("SELECT 1 FROM incidents WHERE build_id=? AND published=1 AND time_kind IS NULL LIMIT 1", (build_id,)).fetchone():
                limitations.append("Some incidents use original line order only; elapsed time and chronological order cannot be established for those records.")
            if connection.execute("SELECT 1 FROM incidents WHERE build_id=? AND published=1 AND time_kind IN ('naive','yearless') LIMIT 1", (build_id,)).fetchone():
                limitations.append("Naive/yearless timestamps are compared only as a common relative clock; no timezone/year is invented and clock regressions split episodes.")
            if connection.execute("SELECT 1 FROM incidents WHERE build_id=? AND published=1 AND actor_key='' LIMIT 1", (build_id,)).fetchone():
                limitations.append("Some observations have no source identifier; any account-only association lacks source attribution.")
            if connection.execute("SELECT 1 FROM incidents WHERE build_id=? AND published=1 AND category='authentication' AND account_key='' LIMIT 1", (build_id,)).fetchone():
                limitations.append("Some authentication observations have no account name; source/target association does not establish the same account.")
            if connection.execute("SELECT 1 FROM incidents WHERE build_id=? AND published=1 AND target_key='' LIMIT 1", (build_id,)).fetchone():
                limitations.append("Some observations lack a service/target; association uses only available source/account fields.")
            if run is None:
                limitations.append("AI inference has not been started; this report currently contains deterministic correlations only.")
            elif run["status"] != "completed":
                limitations.append("AI processing is incomplete; completed findings and all indexed deterministic observations are retained.")
            if indexed_chunks < job["total_chunks"] or job["status"] != "ready":
                limitations.append("Log preparation/event indexing is incomplete; evidence coverage may be partial.")
            if build["revision"] != state["revision"]:
                limitations.append("New evidence arrived while correlation was built; request the report again for the latest snapshot.")
            if build["ignored_ai"]:
                limitations.append(f"{build['ignored_ai']} AI candidate(s) did not meet a supported category and evidence rule and were excluded; generic errors alone are not attacks.")
            errors = []
            if job["error_code"]:
                errors.append({"stage": "preparation", "code": job["error_code"], "message": job["error_message"]})
            if run and run["error_code"]:
                errors.append({"stage": "inference", "code": run["error_code"], "message": run["error_message"]})
            for error in connection.execute(
                "SELECT error_code,COUNT(*) AS count FROM inference_units WHERE analysis_id=? AND status='failed' GROUP BY error_code LIMIT 20", (analysis_id,),
            ):
                errors.append({"stage": "inference_unit", "code": error["error_code"], "count": error["count"]})
            complete = bool(run and run["status"] == "completed" and job["status"] == "ready"
                            and indexed_chunks == job["total_chunks"] and build["revision"] == state["revision"])
            header = {
                "analysis_id": analysis_id, "analysis_status": status, "filename": job["filename"],
                "report_complete": complete, "processed_chunks": processed, "indexed_chunks": indexed_chunks,
                "total_chunks": job["total_chunks"], "total_findings": sum(severity_counts.values()),
                "finding_counts_by_severity": severity_counts, "correlation_rules": self.correlator.rules,
                "correlation_revision": build["revision"], "limitations": limitations, "analysis_errors": errors,
            }
            yield encode(header)[:-1] + ',"related_identifiers":['
            first = True
            for row in connection.execute(
                "SELECT DISTINCT COALESCE(e.source_ip,e.identifier) FROM incidents i JOIN incident_events l ON l.incident_id=i.id "
                "JOIN security_events e ON e.id=l.event_id WHERE i.build_id=? AND i.published=1 AND COALESCE(e.source_ip,e.identifier) IS NOT NULL ORDER BY 1", (build_id,),
            ):
                yield ("" if first else ",") + encode(row[0])
                first = False
            yield '],"incidents":['
            first = True
            for row in connection.execute("SELECT * FROM incidents WHERE build_id=? AND published=1 ORDER BY start_line,incident_key", (build_id,)):
                if not first:
                    yield ","
                first = False
                metrics = json.loads(row["metrics_json"])
                methods = json.loads(row["methods_json"])
                incident = {
                    "id": row["incident_key"], "category": row["category"], "title": row["title"],
                    "severity": row["severity"], "risk_status": "inferred_possible", "confidence": "possible",
                    "identifier": row["actor_key"][3:] if row["actor_key"] else None,
                    "username": row["account_key"] or None, "target": row["target_key"] if row["target_key"] not in {"", "*"} else None,
                    "start_line": row["start_line"], "end_line": row["end_line"],
                    "timestamp_start": row["timestamp_start"], "timestamp_end": row["timestamp_end"],
                    "time_basis": row["time_kind"] or "line_order_only", "detection_methods": methods,
                    "confirmed_log_events": metrics.get("observed_events", {}), "metrics": metrics,
                    "reason": row["reason"], "suggested_action": row["suggested_action"],
                }
                yield encode(incident)[:-1] + ',"ai_finding_ids":['
                first_ai = True
                for finding in connection.execute("SELECT finding_id FROM incident_ai WHERE incident_id=? ORDER BY finding_id", (row["id"],)):
                    yield ("" if first_ai else ",") + encode(finding[0])
                    first_ai = False
                yield '],"evidence":['
                first_evidence = True
                for evidence in connection.execute(
                    "SELECT DISTINCT e.id,e.line,e.chunk_id,e.start_byte,e.start_char,e.excerpt,c.ordinal FROM incident_events l "
                    "JOIN event_links x ON x.event_id=l.event_id JOIN event_evidence e ON e.id=x.evidence_id JOIN chunks c ON c.id=e.chunk_id "
                    "WHERE l.incident_id=? ORDER BY e.line,e.start_byte,e.id", (row["id"],),
                ):
                    value = {"line": evidence["line"], "chunk_id": evidence["chunk_id"], "chunk_ordinal": evidence["ordinal"],
                             "start_byte": evidence["start_byte"], "start_char": evidence["start_char"], "excerpt": evidence["excerpt"]}
                    yield ("" if first_evidence else ",") + encode(value)
                    first_evidence = False
                yield "]}"
            yield "]}"
