# Local AI Security Log Analyzer

## Purpose and current scope

Build a production-minded, lightweight MVP for a software developer coding assignment.
The target is macOS on Apple Silicon with Python 3.11 or newer. Implement actual,
runnable code with clean imports, useful type hints, and a simple modular structure.
Inspect the repository before editing and preserve useful existing code.

**Phases 1 through 5 are authorized. Stop after Phase 5.** Phase 4 adds persistent
event memory, cross-chunk correlation, deduplication, compact prior context, and a
combined final JSON security report. Phase 5 adds a complete responsive browser
dashboard served by the existing FastAPI/Jinja2 application.
Never hardcode or fabricate AI analysis results.

## Environment preservation and dependency management

- Reuse the user's existing UV-created `.venv`. Never delete, rename, replace, or
  recreate it. If the expected environment is missing, find it or ask the user;
  do not let UV silently create a replacement.
- Inspection for this implementation found an empty project directory, no Git
  repository, no existing metadata or source, and no project-local `.venv`.
- The user directed inspection of `/Users/sakibsmacbookm5/Documents/Python work`.
  The existing environment was found at
  `/Users/sakibsmacbookm5/Documents/Python work/.venv`, using CPython 3.12.13.
- Target that environment with `UV_PROJECT_ENVIRONMENT` in the shell. It also
  contains unrelated projects' packages. Preserve those packages: `uv run` uses
  additive synchronization by default; avoid `uv run --exact` and plain `uv sync`.
  If synchronization is needed, `uv sync --inexact` preserves unrelated packages.
- Reuse `pyproject.toml` and `uv.lock`. Metadata was initialized with `uv init
  --bare` because this checkout originally had none. Do not copy metadata from
  the unrelated project that owns the environment.
- Use `uv add` for dependencies (`uv add --dev` for pytest) and `uv run` for all
  Python commands. `uv add --no-sync` can update metadata and the lock without
  changing the environment; follow with an additive `uv run` when installing.
- After installation, `uv run --offline --no-sync` runs against the existing
  environment without fetching dependencies or creating a new environment.
- Keep `uv.lock` tracked. Do not add torch, transformers, model runtimes, or other
  packages already present in the shared environment to this project's dependencies.

## Required stack and exclusions

- Backend: Python 3.11+ and FastAPI, served with Uvicorn.
- Frontend: vanilla HTML, CSS, JavaScript, and Jinja2 templates.
- Database: SQLite through Python's built-in `sqlite3`; no ORM.
- Local AI: an existing Qwen3.5 0.8B GGUF model served separately by llama.cpp.
- HTTP client: `httpx`. Multipart streaming: `python-multipart`. Tests: `pytest`
  and FastAPI's HTTPX-backed `TestClient`.
- No cloud inference, cloud AI APIs, API keys, or other cloud runtime services.
- No heavy dependencies, React, Node.js, Docker, Redis, Celery, or additional
  application frameworks. Do not install or download the model again.
- All application functionality must work offline after dependencies and the
  model have been installed. No external fonts, scripts, stylesheets, or assets.

## Resource constraints and model contract

- Total model and application RAM budget: **4 GB**.
- Evaluation hardware: **2 CPU threads, no GPU**.
- Model context: **2048 tokens maximum**; expected server logs are approximately
  **20,000 tokens**, so a future phase must not send an entire log in one prompt.
- **Only one AI inference at a time.** Use one backend worker and run llama.cpp
  with one slot (`--parallel 1`). Preserve the shared inference async gate and
  sequential worker. A connection pool
  limit alone is not a complete inference scheduler or cancellation guarantee.
- Count complete chat messages with llama.cpp's tokenizer, including the actual
  server chat template, system instructions, saved context, and evidence labels.
  Always enforce `actual_input_tokens + 384 + 64 <= context_tokens <= 2048`.
  Output reservation is 384 tokens; safety reservation is 64 tokens minimum.
  Never replace the tokenizer with word counts, whitespace splits, or estimates.
- llama.cpp is started by the user in a separate process; FastAPI must never
  launch, supervise, install, or load the model.
- Default base URL: `http://127.0.0.1:8080`.
- Model alias: `qwen-local`.
- Chat endpoint: `/v1/chat/completions`.
- Token counting endpoint: `/v1/chat/completions/input_tokens`.
- Health endpoint: `/health`.
- Bind llama.cpp to loopback. Suggested CPU settings are documented in README.md:
  2048 context, two generation/batch threads, zero GPU layers, one inference slot,
  and modest batch sizes. Actual memory use under load still needs benchmarking.

## Phase 1 acceptance criteria

1. Inspect the repository and existing `.venv` before changes.
2. Create a clean, modular FastAPI application.
3. Centralize environment configuration and validation.
4. Initialize SQLite and provide a simple database access layer.
5. `GET /health` reports backend and SQLite health independently of llama.cpp.
6. `GET /api/model/health` checks actual llama.cpp availability.
7. `GET /` serves an initial Jinja2 HTML page using local CSS and JavaScript.
8. Add useful types, logging, and consistent error responses.
9. Ignore environments, uploaded logs, SQLite data/sidecars, GGUF files, caches,
   and secrets in `.gitignore`; retain `.env.example` and `data/.gitkeep`.
10. Maintain this file with the full requirements and architectural decisions.
11. Run relevant tests or the application, fix observed failures, and report the
    files changed, exact backend launch command, and remaining manual actions.

## Structure and architectural decisions

```text
app/
  __init__.py
  main.py
  config.py
  database.py
  inference_database.py
  event_database.py
  schemas.py
  errors.py
  routes/{__init__,health,pages,analyses}.py
  services/{__init__,model,uploads,parsing,prompts,chunking,preparation}.py
  services/{security_prompts,findings,inference}.py
  services/{event_parsing,correlation,reporting}.py
  templates/index.html
  static/{styles.css,app.js,theme.js,favicon.svg}
tests/
data/.gitkeep
AGENTS.md
README.md
pyproject.toml
uv.lock
.gitignore
.env.example
```

- `main.create_app` is the application factory; `main.app` is Uvicorn's entry
  point. Lifespan initializes SQLite and owns one shared async HTTPX client,
  closing it on shutdown. Importing the application must not create a database,
  launch services, or issue model requests.
- `Settings` is a frozen, standard-library dataclass. Read environment variables
  through `Settings.from_env`; inject explicit settings into tests. No additional
  settings framework or automatic dotenv dependency is needed. Use UV's
  `--env-file .env` to load optional overrides. Resolve data/template/static paths
  from the project root, not the shell's current working directory.
- Fail early on invalid settings. Model URLs accept only HTTP loopback IP
  literals; normalize `localhost` to `127.0.0.1` to avoid DNS resolution. Reject
  remote hosts, wildcard binds, credentials, URL prefixes, queries, and fragments.
  Keep `trust_env=False` and `follow_redirects=False` on model HTTP requests so
  proxies and upstream redirects cannot send traffic outside loopback.
- Bound model health requests with HTTPX timeouts and an overall async deadline
  including connection-pool wait and response body. Phase 3 uses two HTTP
  connections so health/tokenization do not wait behind generation; the shared
  inference lock still permits only one generation. Model unavailability must not prevent backend startup or access to
  the initial page. Readiness requires HTTP 200 with JSON `{"status":"ok"}`;
  availability does not verify model identity or perform a generation.
- SQLite is initialized idempotently with WAL and foreign keys. Use short-lived
  connections, parameterized SQL, explicit commit/rollback, and guaranteed close.
  Run blocking SQLite work outside the async event loop. Schema version `4`
  migrates versions `1`, `2`, and `3` transactionally. Keep original analyses/chunks
  and metadata intact; inference uses separate checkpoint/attempt/finding tables.
  Reject unsupported schema versions without overwriting their version marker.
- JSON errors follow `{"error":{"code":"...","message":"..."}}` with an
  appropriate HTTP status. Unavailable database/model returns 503; missing routes
  return 404; invalid input returns 422; unexpected failures return a generic 500.
  Do not expose tracebacks, SQL, validation inputs, or upstream response bodies.
- Use standard-library UTC logging for startup/shutdown, method, route pattern,
  status, latency, and generated request ID. Do not log secrets, query strings,
  raw log contents, prompts, or model responses. Include `X-Request-ID` in HTTP
  responses. Serve a restrictive same-origin CSP and no external browser assets.
- Keep the backend bound to `127.0.0.1` with one worker. Do not enable permissive
  CORS. FastAPI's CDN-backed Swagger/ReDoc pages are disabled for offline use;
  `/openapi.json` remains available locally.
- The HTML dashboard fetches the two health endpoints on load and on refresh.
  Show real state and accessible status text. Upload, inference controls, filters,
  evidence and JSON export must work; never show fictitious analysis results.

## Phase 2 requirements and decisions

- `POST /api/analyses` accepts exactly one multipart `file` with a `.log` or `.txt`
  suffix (case-insensitive). Validate extension, declared MIME type, actual text,
  and actual byte count. Default `MAX_UPLOAD_BYTES=10485760` (10 MiB), configurable.
  Reject unsupported types, invalid UTF-8, binary/control bytes, empty or
  whitespace-only files, malformed/truncated multipart, and oversized files.
- Do not call `request.body()`, `request.form()`, an unbounded `read()`, or an
  unbounded `readline()`. Parse `request.stream()` incrementally with
  python-multipart, feeding at most 64 KiB per call on a worker thread. Independently
  bound multipart headers and total envelope overhead; do not trust Content-Length.
- Generate a UUIDv4 for every accepted analysis. Uploaded names are display
  metadata only: normalize to a basename and never use them in a filesystem path.
  Store mode-0600 files under `DATA_DIR/uploads/<uuid>.part`, validate and fsync,
  then atomically rename to `<uuid>.log` before queueing the job. Clean invalid
  partial files. Keep the original bytes and a SHA-256 digest for valid uploads.
- Persist job metadata/status/errors/timestamps in SQLite. Return HTTP 202 with
  `{"id":"<uuid>","status":"queued"}` after validation and queue commit.
  Status advances `uploading -> queued -> processing -> ready` or `failed`.
  `ready` means prepared evidence, never completed AI analysis.
- Run one in-process preparation worker backed by the durable SQLite queue; do
  not use Celery, Redis, or a list of all jobs in memory. Claim jobs transactionally.
  Cancel cleanly on shutdown. At startup, requeue interrupted preparation after
  deleting partial chunks; mark interrupted uploads failed and clean UUID-owned
  partial/orphan files. Preserve already-ready jobs. Deploy one backend worker.
- Sequentially parse UTF-8 logs with bounded 4096-character reads and lookahead.
  Preserve original LF/CRLF/CR, BOM, blank lines, final-newline state, and raw text.
  Original line numbers are 1-based; byte/character ranges are 0-based, half-open.
  Never execute, evaluate, interpolate into shell commands, or follow instructions
  from uploaded content. Every entry is untrusted evidence.
- Extract common access-log timestamp/IP/user/method/path/status and common auth-log
  timestamp/IP/user fields where recognizable. Unknown or mixed formats remain
  valid; raw evidence is authoritative and must not be replaced by parsed fields.
- `PromptBuilder` is the shared immutable interface for the exact system prompt,
  saved context, model alias, template options, messages, and output limit. Inject
  it via `create_app(prompt_builder=...)`; snapshot it per analysis in SQLite.
  Serialize log data as JSON in a user message, with explicit untrusted-data
  instructions in the system message. No user-supplied system-prompt upload fields.
- Tokenize complete `PromptBuilder.build(entries)` payloads through
  `/v1/chat/completions/input_tokens`. Store the exact counted payload alongside
  its count. The default input ceiling is `2048 - 384 - 64 = 1600` tokens.
  Fail closed if the tokenizer is unavailable/invalid or the prompt leaves no room.
  Never truncate or silently skip evidence to make a chunk fit.
- Bound the packing window to 64 entries or approximately 16 Ki characters (plus
  one bounded read). Rejoin adjacent reader segments of one line when they fit
  this window. Try a whole batch, then bounded binary searches over whole-entry
  prefixes. Split a too-long entry by verified character-prefix searches and mark
  fragments with original line and exact offsets. Counts, not character lengths,
  authorize emission; conservative packing need not maximize every chunk's fill.
- Persist each chunk immediately, keeping only the bounded window in memory.
  Record UUID, analysis ID, ordinal, start/end line, start/end byte, actual input
  tokens, status, creation time, entries, and exact chat payload. Failure marks any
  partial chunks failed. Interrupted jobs rebuild chunks from their original file.
- Verify contiguous evidence byte ranges, exact file size, and a rolling SHA-256
  before declaring the analysis ready. No missing, duplicated, reordered, normalized,
  or overlap text is permitted between chunks. Blank lines count as original lines.
- `GET /api/analyses/{id}` returns public metadata/status/errors.
  `GET /api/analyses/{id}/chunks` returns paginated metadata (default 20, max 100).
  `GET /api/analyses/{id}/chunks/{chunk_id}` returns one bounded chunk's evidence
  and exact payload. Do not expose filesystem paths or stream all chunks at once.
- Later inference must re-tokenize/rechunk if prompts, context, model, or server
  template change. A persisted count is valid for its exact messages and template;
  do not append a new prompt or saved summary without checking the budget again.
- Retained preparation limits: UTF-8 text only, best-effort format extraction,
  and one backend process. Preparation failures still require fixing the cause
  and reuploading. Phase 3 inference retries are described below.

## Phase 3 requirements and decisions

- Inference is exclusively through the existing local Qwen3.5 0.8B llama.cpp
  `POST /v1/chat/completions`. Never use cloud AI APIs for logs, download models,
  start llama.cpp, or import heavy ML libraries into FastAPI.
- Reuse the lifespan HTTPX client with loopback validation, disabled proxies and
  redirects, a two-connection bounded pool, and a shared inference lock. The inference
  worker processes one job, source chunk, and bounded unit at a time. Generation
  uses the configured alias (`qwen-local`), `max_tokens=384`, `temperature=0.1`,
  and `stream=false`. These generation limits cannot be overridden by payloads.
- Count the exact complete payload inside the inference lock immediately before
  every generation POST, even on retries and even when a planning count exists.
  Reject any request violating `input_tokens + 384 + 64 <= min(context_tokens,2048)`.
  Keep template options, JSON formatting options, instructions, saved context,
  and evidence labels in that same payload. Never use word-count estimates.
- `SecurityPromptBuilder` extends the shared prompt interface. The concise system
  prompt asks for defensive analysis of brute force, SQL injection, scanning,
  unauthorized access, and unusual rates, while distinguishing ordinary errors.
  It treats all evidence/context as untrusted, ignores embedded instructions,
  prohibits fabricated entities/citations and command execution, prefers short
  output, and permits `{"findings":[]}` when evidence is insufficient.
- `POST /api/analyses/{id}/start` requires prepared `ready` evidence. It creates
  a durable inference run or resumes unfinished work after failure. Repeated
  starts while queued/running/completed do not reset completed work or findings.
  Uploading alone must never trigger inference. Existing Phase 2 jobs are supported.
- Keep original prepared chunks unchanged. Snapshot the security prompt, alias,
  context cap, and saved context when starting a run. Compact saved context to at
  most 512 characters and reduce further if needed; never truncate raw evidence.
  Repack each bounded prepared chunk using the existing tokenizer-aware packer.
  Persist inference units one by one with original line/byte ranges and exact
  counted payloads. No whole-file reads or all-chunk lists. Phase 4 adds bounded
  prior context backed by the event store, not a full-history prompt.
- If the live pre-call count no longer fits, checkpoint replacement subunits
  with empty saved context before processing them. Parent units become superseded;
  completed siblings remain untouched. Bound recursive re-planning to three levels,
  and fail closed if the prompt itself cannot fit. Plan construction and recovery
  must never introduce missing, duplicated, or reordered raw evidence.
- Use Pydantic with strict types and forbidden extra keys for `FindingBatch`,
  `SecurityFinding`, and `FindingEvidence`. The JSON contract requires attack_type,
  severity (Low/Medium/High/Critical), identifier, evidence [{line,excerpt}], reason,
  suggested_action, and confidence. Confidence is conservatively restricted to
  `possible`; there is no `confirmed` state. Reasons/actions must contain text.
  Keep field/list lengths bounded to fit the small model and output budget.
- Verify each cited original line belongs to that inference unit and its excerpt
  is an exact substring of the corresponding supplied range. Never stitch across
  missing fragments. Nonempty identifiers must occur in cited excerpts with entity
  boundaries. Reject invented IPs in narrative fields. Verify bounded raw byte
  ranges against the original upload before generation and again before storing.
- Store only validated model candidates, labeled `evidence_verified`. Citation
  verification proves the quoted text exists, not that an attack is confirmed or
  the model's interpretation is correct. Invalid findings never enter the findings
  table. Do not present raw model suspicions as confirmed security facts.
- Use schema-constrained JSON formatting by default (`auto`). If llama.cpp
  explicitly rejects format/schema/grammar options, downgrade through plain JSON
  object formatting to no format hint within the same bounded attempt budget.
  Always retain strict parsing and evidence validation after a downgrade.
- Try strict JSON first, optionally strip one surrounding Markdown fence, then
  cautiously extract the first complete object. Reject ambiguous multiple objects,
  duplicate keys, non-finite numbers, missing fields, malformed/truncated JSON,
  and invalid evidence. Never cherry-pick a nested object from truncated output,
  execute output, or feed malformed output back as prompt instructions.
- Default `INFERENCE_MAX_ATTEMPTS=3` (1..5), timeout 120 seconds (up to 600),
  short exponential backoff starting at 0.25 seconds (bounded to 2 seconds).
  Recoverable connection/server/timeout/JSON/evidence errors get bounded retries.
  A permanently malformed unit fails while later units/chunks can continue.
  Infrastructure outages pause remaining work with clear failed/partial status.
- A timeout, disconnect after sending, or cancellation can leave server generation
  active. Preserve uncertainty. Before another generation, verify all llama.cpp
  `/slots` have `is_processing=false`, with a bounded five-second probe. If slots
  are disabled, invalid, or still busy, fail closed as `model_state_uncertain`;
  do not immediately resend. Keep llama.cpp at `--parallel 1` as a second guard.
  Recover uncertainty from interrupted attempt checkpoints across application restarts.
- Schema 3 adds `inference_runs`, `inference_chunks`, `inference_units`,
  `inference_attempts`, and `findings`. Store source-chunk progress, bounded unit
  plans, timing, actual input tokens, cumulative/per-resume attempt counts, errors,
  and timestamps. Save findings and completed-unit state in one SQLite transaction.
  A unique `(unit_id,fingerprint)` prevents duplicate findings on retry.
- Checkpoint every unit before advancing. On startup, retain completed units and
  findings, recover pending/interrupted units, discard only unfinished plans, and
  requeue previously running jobs. Retry counts survive a crash. An explicit
  `/start` after partial/failure grants a fresh bounded attempt round only to
  unfinished work; it never regenerates completed findings.
- `GET /api/analyses/{id}` exposes effective status queued/running/completed/
  partially_completed/failed after inference starts, with original preparation
  status separately and an `inference` progress object. Chunk APIs include inference
  timing/counts/state. `/findings` and `/attempts` are paginated raw inspection APIs,
  remain raw inspection APIs. Use `/report` for merged, correlated incidents.
- Attempt diagnostics contain request/response hashes, bounded response length,
  HTTP status, recovery/error codes, tokens, and timing. Never persist failed raw
  responses, prompts again in diagnostics, exception messages containing evidence,
  or sensitive log content beyond necessary source evidence/validated findings.
- Inference responses are capped at 64 KiB; JSON content at 32 KiB. No new runtime
  dependencies are required for Phase 3. Keep low RAM by processing one bounded
  evidence window/unit and paginating data access. Phase 5 now adds the browser
  dashboard; automatic actions, cloud services and model downloads remain excluded.

## Phase 4 requirements and decisions

- The final result must correlate across all chunks, not concatenate per-chunk AI
  outputs. Events at original lines 100, 5000, and 9000 may belong to one incident.
  Detection must work even when AI returns no findings, prior prompt context is
  dropped, or some AI calls fail. Hardcoded attack outcomes are prohibited outside tests.
- Schema 4 adds `security_events`, bounded `event_evidence`, event/evidence and
  event/AI links, indexing checkpoints, correlation state/builds, incidents, and
  incident/event/AI links. Store analysis ID, original chunk ID/line, literal
  timestamp, comparable clock coordinate/kind, source IP or observed identifier,
  account, target/path, HTTP status, normalized event type, and bounded excerpt.
- Index deterministic events in the same SQLite transaction that saves a prepared
  chunk. Supplement them from already-validated AI citations in the transaction
  that checkpoints findings. A model attack label never establishes an observed
  event: only literal recognizable facts in cited source text may add event rows.
- Backfill legacy prepared/completed analyses incrementally from bounded stored
  chunks/findings. Never rerun completed inference to obtain a report. Retry and
  restart indexing must be idempotent. Keep raw findings/checkpoints intact.
- Parse common access, SSH/auth, explicit detector, and simple JSON log formats.
  Retain explicit failures/successes, denied access, SQL-injection payload patterns,
  sensitive-path probes, and observed HTTP requests needed for rate calculations.
  SQL debug errors and generic 404/500 responses alone are not attack indicators.
  A 200 response to `/login` must never be interpreted as successful authentication.
- Extract source/account fields from their observed roles. Access-log request
  payloads cannot override the leading remote address or remote-user field.
  Client-controlled request/agent authentication phrases cannot establish an
  authentication outcome. Reject malformed/unbounded HTTP-status metadata safely.
  Do not assume a lone destination IP is a source. Missing fields remain null;
  do not invent hosts, usernames, years, timezones, status codes, or targets.
- Exact duplicate original records share one event; retain all original evidence
  references while counting the event once. Partial reader fragments may reuse
  the same normalized event at one original line but cannot deduplicate unrelated
  lines based only on a shared partial string. Deduplicate evidence by original
  analysis/line/byte position/excerpt. Indistinguishable genuine repeated requests
  can be undercounted; disclose that conservative limitation.
- Group authentication/SQL/denials by observed source or identifier, account, and
  relevant normalized target. Decode request paths at most twice and remove query
  strings only for target grouping; retain original paths/excerpts. Scanning and
  request-rate episodes are source-wide. Separate unrelated sources, accounts,
  targets, distant episodes, backward clocks, and incompatible timestamp kinds.
- Use rolling threshold windows inside activity episodes, not fixed UTC buckets
  or all-history totals. Split an episode after an inactivity gap beyond its window,
  a clock regression/kind change, or a new failure burst after an associated success.
  Keep only threshold-bounded timestamps/path counters in RAM; all evidence stays
  in SQLite. Thresholds must not exceed 10000; other window settings are bounded.
- Defaults: 5 auth failures / 1800 seconds; repeated SQL threshold 2 / 600 seconds;
  5 distinct sensitive paths / 300 seconds; 5 denied records / 300 seconds; 100
  distinct requests / 60 seconds. All are centralized environment settings in
  `.env.example`. Missing comparable clocks use at most 10000 original lines for
  conservative association; request rates are never calculated without timestamps.
- Offset-aware timestamps compare actual instants. Naive timestamps use only a
  common relative clock. Yearless syslog clocks use a computational calendar anchor
  without asserting a year; regressions split episodes and output preserves the
  original timestamp. Missing/unsupported timestamps use original record order
  only, with an explicit elapsed-time limitation. Do not bridge missing clocks
  between two incompatible known-time episodes.
- Auth incidents require the configured number of distinct failures in a rolling
  window; a later success must have that many preceding failures in its own window.
  Produce one combined brute-force/success finding, retaining all relevant source
  references. Success alone does not confirm account compromise. Known source,
  account, and offset-aware clock permit High; weaker associations remain Medium.
- SQL patterns yield Medium; repeated patterns meeting the configured threshold
  with an offset-aware clock yield High. Sensitive-path scans and repeated denials
  are Medium; source-level high request rate is Low and can be legitimate traffic.
  No automatic rule asserts Critical/confirmed exploitation. Model-only supported
  assessments are capped at Medium; deterministic severity wins when corroborated.
  Merged model-only severity is order-independent (max under that cap).
- Merge validated AI assessments into the matching category/scope/episode through
  shared event references. Generic error-only or unsupported-category AI candidates
  remain in the raw findings API but are excluded from final incidents, with an
  omission count/limitation. Normalize final titles/reasons rather than copying
  unsupported model claims of confirmed compromise.
- Related source-rate/denial signals can join one unambiguous overlapping security
  incident when original evidence overlaps. Never choose arbitrarily between
  multiple separate targets/accounts. Union methods, observed counts, evidence,
  and AI IDs without double-counting references. Keep genuine incidents separate.
- Compact context queries SQLite for up to three relevant current source/account/
  target scopes, only earlier original lines, and the applicable time/line window.
  Include bounded counters and at most a short prior AI assessment, labeled possible.
  Context is at most 512 characters. Drop whole summaries when token space is tight;
  never truncate source evidence or rely on context for authoritative correlation.
  AI citation-line cutoffs must prevent future findings linked to a deduplicated old
  event from leaking backward during a resumed earlier unit.
- Recount the full changed prompt, including compact memory, and preserve all
  Phase 3 inference gates/output/safety limits. Store the exact context in the
  attempt's checkpointed payload. Correlation remains independent of LLM memory.
- Correlation builds are revision/rule-hash cached, computed from a SQLite read
  snapshot, and atomically published only when complete. Commit derived links in
  bounded batches so inference writes can continue. Public incident IDs derive from
  category/scope/first observation and stay stable when AI support is added.
  Abandoned builds can be removed; never erase completed source findings/events.
  Reserve short write transactions before reading derived metrics/merges; do not
  upgrade a held WAL read snapshot while another worker owns the write lock.
  Ancillary merges fetch and commit batches of at most 128 incidents.
- `GET /api/analyses/{id}/report` returns JSON with analysis/status/filename,
  processed and indexed chunk counts, total incidents, severity counts, related
  identifiers, combined incidents, original evidence references, reason/action,
  limitations and errors. `total_findings` counts merged incidents, not raw AI rows.
  `processed_chunks` counts completed AI chunks; `indexed_chunks` describes
  deterministic coverage. In-progress/partial reports clearly state incompleteness.
- Stream report JSON from a read snapshot; do not build an all-evidence list in
  application RAM. Starlette may advance a sync stream on different worker threads:
  only that sequential read connection uses `cross_thread=True`. Never use it
  concurrently. Normal database operations retain their per-call thread ownership.
  Streaming must remain consistent if a newer correlation build is published.
- `confirmed_log_events` means normalized statements actually present in the log,
  not confirmed real-world attacks. Every incident remains `inferred_possible`.
  If evidence arrives during a build, mark the report incomplete and explain the
  snapshot lag. Preserve completed AI findings in reports after partial failures.
- Event parser/correlation versions are explicit. If future normalization changes,
  migrate/reindex authoritative event projections carefully and invalidate derived
  caches; never silently keep stale fields or delete source findings.
- Phase 4 adds no runtime dependencies, cloud calls, automatic model downloads,
  or automated remediation. Phase 5 supplies the browser dashboard below. Keep
  the existing UV environment.

## Phase 5 requirements and decisions

- Serve the entire dashboard from `GET /`, Jinja2 and same-origin vanilla CSS/JS.
  No React, Node, Tailwind tooling, frontend server, external assets/fonts, CDN,
  cloud APIs, analytics or new application dependencies. Keep the professional
  light/dark themes, responsive layout, simple navigation and minimal optional motion.
- The user requested light mode and removal of visible phase labels. Keep a
  sun/moon theme button in the header. Follow the system color scheme initially,
  remember an explicit light/dark preference locally, and apply it before CSS
  loads via same-origin `theme.js`. Do not use inline scripts or weaken CSP.
  Every panel, input, warning, severity, and evidence block must remain readable
  in both themes. Keep phase milestones in internal docs, not the product UI.
- Provide drag/drop and keyboard-accessible browse selection, selected filename/
  size, remove, upload, loading/success/error states. Accept one `.log`/`.txt` file.
  Check extension, nonempty size and the server-configured size limit in the UI;
  inject `max_upload_bytes` through an escaped numeric data attribute. Do not read
  file contents in JavaScript. Backend streaming/content validation is authoritative.
- Reuse `POST /api/analyses`, `GET /api/analyses/{id}`, `POST .../start`, health
  endpoints and `GET .../report`. Keep all detection, queueing, checkpoint/retry,
  threshold, token-budget and correlation logic in Python. No dashboard-only job
  queue or duplicate report/detection implementation.
- Extend existing inference status additively with nullable `current_chunk`, from
  the actual running SQLite chunk ordinal. Never infer it from completed counts:
  retries can resume an earlier chunk. Show total/completed/current chunks, progress
  and run wall time from server timestamps. Show indeterminate preparation progress;
  `ready` means prepared and waiting for an explicit start, not analyzed.
- Start locks immediately while a POST/status refresh is pending, disable while
  queued/running/completed, and use the existing idempotent start API. After partial/
  failed inference, offer retry of unfinished checkpoints. Preparation failure
  needs reupload. A lost POST response must reconcile through durable status.
- Use sequential timeout-based polling every 2 seconds while preparing/queued/
  running; no overlapping status requests. Stop at ready/completed/partial/failed,
  after 3 connection failures, or on pagehide. Manual refresh reconnects. Refresh
  health at most once per 15 seconds during active polling; terminal pages do not
  keep background timers. Avoid fetching/rebuilding the whole report per poll.
- Read reports on terminal states and explicit refresh. A final report must replace
  an in-flight interim snapshot. Epoch guards ignore stale responses after changing
  analysis; reset filters when opening a different job. Restore a validated UUID
  from `?analysis=<uuid>` or localStorage; store only that ID, never log/report data.
  A form can open an existing analysis without rerunning inference.
- Show backend severity counts and combined incident cards: title, severity,
  identifier, account/target, literal timestamps, reason, suggested action, and
  expandable original evidence with original line and chunk numbers. Every
  security assessment remains possible; a successful login never confirms compromise.
- Filter by severity, category/attack type and identifier substring. The multiple-
  evidence filter requires distinct original line numbers, not multiple fragments
  of one line. Debounce search, paginate at 12 cards and render evidence lazily in
  batches of 50 to bound DOM size. Display filters do not affect JSON exports.
- All log/model/filename/error/identifier strings use textContent, createTextNode
  or escaped Jinja text. Never use innerHTML, insertAdjacentHTML, document.write,
  eval, executable event attributes, or render source paths as clickable commands.
  Keep CSP and same-origin/network restrictions intact.
- JSON download uses the actual existing report endpoint with `?download=true`.
  Add a safe UUID-only Content-Disposition filename and stream the JSON as before.
  Use a native same-origin download link, avoiding another full report/blob copy
  in browser memory. Report only that a download was requested, not that it saved.
- Handle missing/unsupported/empty/oversized/binary uploads; model/backend outage;
  preparation/chunk failures; incomplete reports; empty/no-matching/no-finding
  reports. Show the neutral no-findings wording: "No suspicious activity was
  identified in the analyzed data." Never claim the server is definitely secure.
  Display coverage limitations and preserve available findings after partial AI failure.
- Default pytest stays fast and model/browser-independent. Optional
  `RUN_BROWSER_TESTS=1` exercises installed Chrome headlessly against an isolated
  loopback backend, temporary SQLite/files and a mocked local model. The stdlib
  DevTools helper in tests introduces no application/runtime dependencies or model/
  browser downloads. `CHROME_PATH` overrides the existing browser executable.
  Optional `PHASE5_SCREENSHOT_DIR` saves QA screenshots; never show test fixtures
  as real analysis data in the shipped application.
- Stop after Phase 5. Do not add later-phase features or automatically publish.

## Verification

After exporting `UV_PROJECT_ENVIRONMENT` to the existing environment:

```sh
uv run --offline --no-sync pytest -q
RUN_MODEL_INTEGRATION=1 uv run --offline --no-sync pytest -q -m integration
RUN_INFERENCE_INTEGRATION=1 uv run --offline --no-sync pytest -q tests/test_inference_integration.py
uv run --offline --no-sync uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

Unit tests use temporary SQLite files and mocked HTTPX transports, never a downloaded
model, cloud connection, real inference, or the user's database. Cover startup,
backend/page/static delivery, database persistence and rollback, SQLite failures,
model readiness/failure/timeout/invalid JSON/redirects, URL restrictions, config,
error sanitization, and resource cleanup. Phase 2 tests must cover valid .log/.txt,
unsupported types, empty and oversized/binary files, a very long single line,
original line numbers, exact no-gap/no-duplicate coverage, actual complete-prompt
token budgets, and an approximately 20,000-token log. Check bounded reads, multipart
fragmentation, schema migration, and interrupted preparation as well.
The Phase 2 opt-in integration tests use the existing local llama.cpp tokenizer, never generation;
they calibrate a roughly 20,000-token fixture, prepare it through the API, independently
recount saved payloads, and verify a rolling evidence hash. Run them when the server
is available, and clearly distinguish them from mocked unit coverage. The separately
opted-in Phase 3 integration test performs real local Qwen inference on synthetic
evidence, validates the result, and may save a sample with `PHASE3_SAMPLE_PATH`.
Test valid/empty/malformed JSON, evidence rejection, injection data, retries/timeouts,
uncertain-server handling, sequential processing, resume without duplicates, partial
findings, original-file changes, and token-budget rejection/re-planning.
Phase 4 uses a streamed 9000-line synthetic fixture, with failures in source
chunks 1/5 and success in source chunk 10. Its explicit source boundaries isolate
correlation from tokenizer packing; inference still repacks and checks every call.
Also test the normal upload pipeline, SQL merging, separate attackers/accounts/
targets/windows, ordinary errors, duplicate records, missing/backward clocks,
compact context relevance/no future leakage, partial AI failures, legacy backfill,
cache invalidation, and the report generator's sequential thread handoff.
To save the actual synthetic report:
`PHASE4_REPORT_PATH=data/phase4-demo-report.json uv run --offline --no-sync pytest -q tests/test_correlation.py::test_distant_chunk_1_5_10_authentication_is_one_final_finding`.
Stop after Phase 5.
