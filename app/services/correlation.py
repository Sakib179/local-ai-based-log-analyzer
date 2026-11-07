"""Persistent, conservative episode correlation across all prepared chunks."""

import json
import sqlite3
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from threading import RLock
from uuid import uuid4

from app.config import Settings
from app.database import Database
from app.event_database import EventStore, fingerprint

ENGINE_VERSION = 1
ACTIONS = {
    "authentication": "Review authentication and session records; investigate the source and account, and consider rate limits or MFA.",
    "sql_injection": "Investigate the requests, validate query parameter handling, and use parameterized database queries.",
    "scanning": "Review the source and requested sensitive paths; restrict unnecessary endpoints and consider rate limits.",
    "unauthorized": "Review access policy and denied requests; investigate repeated attempts against the target.",
    "request_rate": "Compare the source rate with legitimate traffic and consider appropriate rate limiting.",
}


def attack_category(text: str) -> str | None:
    text = text.lower()
    if "sqli" in text.split() or "sql" in text and ("inject" in text or "attack" in text):
        return "sql_injection"
    if any(word in text for word in ("brute", "authentication", "login", "credential", "account compromise")):
        return "authentication"
    if any(word in text for word in ("scan", "traversal", "reconnaissance", "sensitive path")):
        return "scanning"
    if "unauthor" in text or "access denied" in text:
        return "unauthorized"
    if any(word in text for word in ("request rate", "flood", "denial of service")):
        return "request_rate"
    return None


@dataclass
class Episode:
    id: str
    key: str
    first: dict
    last: dict
    counts: Counter = field(default_factory=Counter)
    preceding_failures: int = 0
    qualifying_successes: int = 0
    qualified_window: bool = False
    recent: deque = field(default_factory=deque)
    paths: dict = field(default_factory=dict)


class Correlator:
    def __init__(self, database: Database, events: EventStore, settings: Settings) -> None:
        self.database, self.events, self.settings = database, events, settings
        self.lock = RLock()
        self.rules = {k: v for k, v in asdict(settings).items() if k in {
            "auth_failure_threshold", "auth_window_seconds", "correlation_line_window", "sql_repeat_threshold",
            "sql_window_seconds", "scan_path_threshold", "scan_window_seconds", "unauthorized_threshold",
            "request_rate_threshold", "request_rate_window_seconds",
            "unauthorized_window_seconds",
        }}
        self.rules_hash = fingerprint(ENGINE_VERSION, self.rules)

    def _window(self, category: str) -> int:
        return {
            "authentication": self.settings.auth_window_seconds,
            "sql_injection": self.settings.sql_window_seconds,
            "scanning": self.settings.scan_window_seconds,
            "unauthorized": self.settings.unauthorized_window_seconds,
            "request_rate": self.settings.request_rate_window_seconds,
        }[category]

    def _boundary(self, episode: Episode, event: dict) -> bool:
        first, last = episode.first, episode.last
        if event["category"] == "authentication" and episode.qualifying_successes and event["event_type"] == "auth_failure":
            return True  # A new failure burst after the associated success is a new episode.
        if event["time_kind"] != first["time_kind"]:
            return True  # Missing clocks must not bridge two known, separate windows.
        if event["time_value"] is not None:
            return event["time_value"] < last["time_value"] or event["time_value"] - last["time_value"] > self._window(event["category"])
        return event["line"] - last["line"] > self.settings.correlation_line_window

    def _threshold(self, category: str) -> int:
        return {"authentication": self.settings.auth_failure_threshold, "sql_injection": self.settings.sql_repeat_threshold,
                "scanning": self.settings.scan_path_threshold, "unauthorized": self.settings.unauthorized_threshold,
                "request_rate": self.settings.request_rate_threshold}[category]

    def _within(self, older: dict, event: dict) -> bool:
        if event["time_value"] is not None:
            return 0 <= event["time_value"] - older["time_value"] <= self._window(event["category"])
        return event["line"] - older["line"] <= self.settings.correlation_line_window

    def _observe(self, reader: sqlite3.Connection, episode: Episode, event: dict) -> None:
        category = event["category"]
        threshold = self._threshold(category)
        if category == "scanning":
            if not episode.qualified_window:
                episode.paths = {path: mark for path, mark in episode.paths.items() if self._within(mark, event)}
                episode.paths[event["target"]] = {"line": event["line"], "time_value": event["time_value"]}
                episode.qualified_window = len(episode.paths) >= threshold
        elif event["event_type"] != "auth_success":
            episode.recent.append({"line": event["line"], "time_value": event["time_value"]})
            while len(episode.recent) > threshold:
                episode.recent.popleft()
            if len(episode.recent) == threshold and self._within(episode.recent[0], event):
                episode.qualified_window = True
        else:
            if len(episode.recent) == threshold and self._within(episode.recent[0], event):
                if not episode.qualifying_successes:
                    arguments = [event["analysis_id"], event["actor_key"], event["account_key"], event["target_key"], episode.first["line"], event["line"]]
                    query = "SELECT COUNT(*) FROM security_events WHERE analysis_id=? AND category='authentication' AND actor_key=? AND account_key=? AND target_key=? AND event_type='auth_failure' AND line>=? AND line<?"
                    if event["time_value"] is not None:
                        query += " AND time_kind=? AND time_value BETWEEN ? AND ?"
                        arguments += [event["time_kind"], event["time_value"] - self._window(category), event["time_value"]]
                    else:
                        query += " AND time_kind IS NULL AND line>=?"
                        arguments.append(event["line"] - self.settings.correlation_line_window)
                    episode.preceding_failures = reader.execute(query, arguments).fetchone()[0]
                episode.qualifying_successes += 1

    def _new_episode(self, writer: sqlite3.Connection, build_id: str, event: dict) -> Episode:
        key = fingerprint(event["analysis_id"], event["category"], event["actor_key"], event["account_key"], event["target_key"], event["id"])
        internal_id = fingerprint(build_id, key)
        writer.execute(
            "INSERT INTO incidents (id,incident_key,build_id,analysis_id,category,actor_key,account_key,target_key,time_kind,time_start,time_end,timestamp_start,timestamp_end,start_line,end_line) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (internal_id, key, build_id, event["analysis_id"], event["category"], event["actor_key"], event["account_key"], event["target_key"],
             event["time_kind"], event["time_value"], event["time_value"], event["timestamp"], event["timestamp"], event["line"], event["line"]),
        )
        return Episode(internal_id, key, event, event)

    def _finish_episode(self, writer: sqlite3.Connection, episode: Episode) -> None:
        if not writer.in_transaction:
            # Reserve the short write transaction before reading derived metrics;
            # a deferred read->write upgrade can fail immediately under WAL.
            writer.execute("BEGIN IMMEDIATE")
        category = episode.first["category"]
        counts = episode.counts
        failures = counts["auth_failure"]
        distinct_paths = writer.execute(
            "SELECT COUNT(DISTINCT e.target) FROM incident_events l JOIN security_events e ON e.id=l.event_id WHERE l.incident_id=? AND e.event_type='suspicious_path'", (episode.id,),
        ).fetchone()[0]
        scopes = []
        if episode.first["actor_key"]:
            scopes.append("source")
        if episode.first["account_key"]:
            scopes.append("account")
        if episode.first["target_key"] not in {"", "*"}:
            scopes.append("target")
        scope = "/".join(scopes) or "individual record"
        publish, severity, title, reason = False, "Low", "", ""
        if category == "authentication" and episode.qualified_window:
            publish, severity = True, "Medium"
            if episode.qualifying_successes:
                severity = "High" if episode.first["time_kind"] == "offset" and episode.first["actor_key"] and episode.first["account_key"] else "Medium"
                title = "Possible brute-force activity followed by successful authentication"
                reason = f"{episode.preceding_failures} distinct failed authentication records precede a successful authentication for the same {scope}. Account compromise is possible, not confirmed."
            else:
                title = "Possible brute-force authentication activity"
                reason = f"At least {self.settings.auth_failure_threshold} distinct failed authentication records share the same {scope} in a rolling correlation window ({failures} in the episode)."
        elif category == "sql_injection" and counts["sql_injection_pattern"]:
            publish = True
            severity = "High" if episode.qualified_window and episode.first["time_kind"] == "offset" else "Medium"
            title = "Possible SQL injection attempts"
            reason = f"{counts['sql_injection_pattern']} distinct requests or explicit detector records contain SQL-injection indicators for the same {scope}. Exploitation is not confirmed."
        elif category == "scanning" and episode.qualified_window:
            publish, severity, title = True, "Medium", "Possible scanning of sensitive paths"
            reason = f"The same source requested at least {self.settings.scan_path_threshold} distinct sensitive paths in a rolling window ({distinct_paths} in the episode); generic 404 responses alone were not used."
        elif category == "unauthorized" and episode.qualified_window:
            publish, severity, title = True, "Medium", "Repeated unauthorized requests"
            reason = f"At least {self.settings.unauthorized_threshold} distinct denied-access records share the same {scope} in a rolling window; successful access is not established."
        elif category == "request_rate" and episode.first["time_kind"] is not None and episode.qualified_window:
            publish, severity, title = True, "Low", "Unusual request rate"
            reason = f"At least {self.settings.request_rate_threshold} distinct request records from the same source occur in a rolling {self.settings.request_rate_window_seconds}-second window; legitimate high traffic remains possible."
        if not episode.first["actor_key"] and category != "sql_injection":
            # Account-only authentication association is weaker than source attribution.
            severity = "Medium" if severity == "High" else severity
        metrics = {"observed_events": dict(counts), "distinct_sensitive_paths": distinct_paths,
                   "failures_before_success": episode.preceding_failures, "qualifying_successes": episode.qualifying_successes,
                   "rolling_window_threshold_met": episode.qualified_window}
        writer.execute(
            "UPDATE incidents SET time_end=?,timestamp_end=?,end_line=?,published=?,severity=?,title=?,reason=?,suggested_action=?,metrics_json=?,methods_json=? WHERE id=?",
            (episode.last["time_value"], episode.last["timestamp"], episode.last["line"], int(publish), severity, title, reason,
             ACTIONS[category], json.dumps(metrics), json.dumps(["deterministic"] if publish else []), episode.id),
        )

    def _episodes(self, reader: sqlite3.Connection, writer: sqlite3.Connection, analysis_id: str, build_id: str) -> None:
        groups = reader.execute(
            "SELECT DISTINCT category,actor_key,account_key,target_key FROM security_events WHERE analysis_id=? ORDER BY category,actor_key,account_key,target_key", (analysis_id,),
        )
        for group in groups:
            category, actor, account, target = group
            if not actor and not (category == "authentication" and account) and category != "sql_injection":
                continue
            episode: Episode | None = None
            pending_links: list[tuple[str, str]] = []
            for row in reader.execute(
                "SELECT * FROM security_events WHERE analysis_id=? AND category=? AND actor_key=? AND account_key=? AND target_key=? ORDER BY line,id",
                (analysis_id, category, actor, account, target),
            ):
                event = dict(row)
                if category == "request_rate" and event["time_kind"] is None:
                    continue  # No clock means no rate calculation.
                if episode and (self._boundary(episode, event) or not actor and category == "sql_injection"):
                    if pending_links:
                        writer.executemany("INSERT OR IGNORE INTO incident_events VALUES (?,?)", pending_links)
                    pending_links.clear()
                    self._finish_episode(writer, episode)
                    episode = None
                if episode is None:
                    if category == "authentication" and event["event_type"] == "auth_success":
                        continue
                    episode = self._new_episode(writer, build_id, event)
                episode.last = event
                self._observe(reader, episode, event)
                episode.counts[event["event_type"]] += 1
                pending_links.append((episode.id, event["id"]))
                if len(pending_links) >= 128:
                    writer.executemany("INSERT OR IGNORE INTO incident_events VALUES (?,?)", pending_links)
                    pending_links.clear()
                    writer.commit()  # Do not block inference checkpoints with a long write transaction.
            if pending_links:
                writer.executemany("INSERT OR IGNORE INTO incident_events VALUES (?,?)", pending_links)
            if episode:
                self._finish_episode(writer, episode)
            writer.commit()

    def _merge_ai(self, reader: sqlite3.Connection, writer: sqlite3.Connection, analysis_id: str, build_id: str) -> int:
        ignored = 0
        for finding_row in reader.execute("SELECT id,finding_json FROM findings WHERE analysis_id=? ORDER BY created_at,id", (analysis_id,)):
            finding = json.loads(finding_row["finding_json"])
            category = attack_category(finding["attack_type"])
            matched = False
            if category:
                # Only literal supporting event types may supplement a correlated
                # incident. A generic 404/500 quote cannot validate an attack label.
                for incident in writer.execute(
                    "SELECT DISTINCT i.* FROM incidents i JOIN incident_events l ON l.incident_id=i.id "
                    "JOIN event_ai a ON a.event_id=l.event_id WHERE i.build_id=? AND i.category=? AND a.finding_id=?",
                    (build_id, category, finding_row["id"]),
                ).fetchall():
                    metrics = json.loads(incident["metrics_json"])
                    observed = metrics.get("observed_events", {})
                    supported = {
                        "authentication": observed.get("auth_failure", 0) > 0,
                        "sql_injection": observed.get("sql_injection_pattern", 0) > 0,
                        "scanning": observed.get("suspicious_path", 0) > 0,
                        "unauthorized": observed.get("unauthorized", 0) > 0,
                        "request_rate": bool(incident["published"]),
                    }[category]
                    if not supported:
                        continue
                    matched = True
                    methods = json.loads(incident["methods_json"])
                    if "validated_ai" not in methods:
                        methods.append("validated_ai")
                    if not incident["published"]:
                        severity = "Low" if finding["severity"] == "Low" else "Medium"
                        title = f"Possible {category.replace('_', ' ')} activity (AI assessment)"
                        reason = "Validated AI assessments cite relevant security log events; the deterministic incident threshold was not met. This remains an inferred risk."
                        writer.execute("UPDATE incidents SET published=1,severity=?,title=?,reason=? WHERE id=?", (severity, title, reason, incident["id"]))
                    elif "deterministic" not in methods and incident["severity"] == "Low" and finding["severity"] != "Low":
                        writer.execute("UPDATE incidents SET severity='Medium' WHERE id=?", (incident["id"],))
                    writer.execute("UPDATE incidents SET methods_json=? WHERE id=?", (json.dumps(methods), incident["id"]))
                    writer.execute("INSERT OR IGNORE INTO incident_ai VALUES (?,?)", (incident["id"], finding_row["id"]))
            if not matched:
                ignored += 1
        writer.commit()
        return ignored

    def _merge_rates(self, writer: sqlite3.Connection, build_id: str) -> None:
        after = ""
        while True:
            # Fetch a bounded batch only after reserving the writer. Holding a
            # SELECT cursor and upgrading later races with worker checkpoints.
            writer.execute("BEGIN IMMEDIATE")
            rates = writer.execute(
                "SELECT * FROM incidents WHERE build_id=? AND category IN ('request_rate','unauthorized') AND published=1 AND id>? ORDER BY id LIMIT 128",
                (build_id, after),
            ).fetchall()
            for rate in rates:
                self._merge_rate(writer, build_id, rate)
            writer.commit()
            if not rates:
                break
            after = rates[-1]["id"]

    def _merge_rate(self, writer: sqlite3.Connection, build_id: str, rate: sqlite3.Row) -> None:
        matches = writer.execute(
            "SELECT DISTINCT i.* FROM incidents i JOIN incident_events l ON l.incident_id=i.id "
            "JOIN event_links e ON e.event_id=l.event_id WHERE i.build_id=? AND i.published=1 AND i.category NOT IN ('request_rate','unauthorized') AND i.actor_key=? "
            "AND (?='request_rate' OR (i.account_key=? AND (i.target_key=? OR i.target_key='*'))) AND e.evidence_id IN "
            "(SELECT x.evidence_id FROM incident_events r JOIN event_links x ON x.event_id=r.event_id WHERE r.incident_id=?) LIMIT 2",
            (build_id, rate["actor_key"], rate["category"], rate["account_key"], rate["target_key"], rate["id"]),
        ).fetchall()
        if len(matches) != 1:
            return  # Never choose arbitrarily between separate accounts/targets.
        match = matches[0]
        incident_id = match["id"]
        metrics = json.loads(match["metrics_json"])
        related = json.loads(rate["metrics_json"])["observed_events"]
        metric_key = "related_" + rate["category"]
        metrics[metric_key] = dict(Counter(metrics.get(metric_key, {})) + Counter(related))
        metrics["observed_events"] = dict(Counter(metrics["observed_events"]) + Counter(related))
        methods = list(dict.fromkeys(json.loads(match["methods_json"]) + json.loads(rate["methods_json"])))
        writer.execute("INSERT OR IGNORE INTO incident_events SELECT ?,event_id FROM incident_events WHERE incident_id=?", (incident_id, rate["id"]))
        writer.execute("INSERT OR IGNORE INTO incident_ai SELECT ?,finding_id FROM incident_ai WHERE incident_id=?", (incident_id, rate["id"]))
        writer.execute(
            "UPDATE incidents SET metrics_json=?,methods_json=?,start_line=?,end_line=?,time_start=?,time_end=?,timestamp_start=?,timestamp_end=? WHERE id=?",
            (json.dumps(metrics), json.dumps(methods), min(match["start_line"], rate["start_line"]), max(match["end_line"], rate["end_line"]),
             rate["time_start"] if rate["start_line"] < match["start_line"] else match["time_start"],
             rate["time_end"] if rate["end_line"] > match["end_line"] else match["time_end"],
             rate["timestamp_start"] if rate["start_line"] < match["start_line"] else match["timestamp_start"],
             rate["timestamp_end"] if rate["end_line"] > match["end_line"] else match["timestamp_end"], incident_id),
        )
        writer.execute("UPDATE incidents SET published=0 WHERE id=?", (rate["id"],))

    def refresh(self, analysis_id: str) -> None:
        with self.lock:
            self.events.ensure_indexed(analysis_id)
            with self.database.connection() as writer:
                writer.execute("INSERT OR IGNORE INTO correlation_state (analysis_id) VALUES (?)", (analysis_id,))
                writer.commit()
                with self.database.connection() as reader:
                    reader.execute("BEGIN")
                    state = reader.execute("SELECT * FROM correlation_state WHERE analysis_id=?", (analysis_id,)).fetchone()
                    cached = reader.execute("SELECT * FROM correlation_builds WHERE id=?", (state["published_build"],)).fetchone()
                    if cached and cached["revision"] == state["revision"] and cached["rules_hash"] == self.rules_hash:
                        return
                    # Remove abandoned, unpublished builds from interrupted report generation.
                    writer.execute("DELETE FROM correlation_builds WHERE analysis_id=? AND status='building'", (analysis_id,))
                    build_id = str(uuid4())
                    writer.execute("INSERT INTO correlation_builds (id,analysis_id,revision,rules_hash) VALUES (?,?,?,?)", (build_id, analysis_id, state["revision"], self.rules_hash))
                    writer.commit()
                    self._episodes(reader, writer, analysis_id, build_id)
                    ignored = self._merge_ai(reader, writer, analysis_id, build_id)
                    self._merge_rates(writer, build_id)
                    writer.execute("UPDATE correlation_builds SET status='complete',ignored_ai=? WHERE id=?", (ignored, build_id))
                    writer.execute("UPDATE correlation_state SET published_build=? WHERE analysis_id=?", (build_id, analysis_id))
                    writer.commit()
                writer.execute("DELETE FROM correlation_builds WHERE analysis_id=? AND id!=?", (analysis_id, build_id))
