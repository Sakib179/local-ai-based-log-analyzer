# Local AI Security Log Analyzer

A lightweight, offline FastAPI foundation for a local security log analyzer.
The responsive light/dark dashboard provides streaming upload, analysis
control, cross-chunk security findings, evidence review, filtering and JSON export.
All inference uses your separately started local llama.cpp server.

## Use the existing environment

The project directory was initially empty. Your UV-created Python 3.12 environment
was found here and reused without recreating it:

```sh
export UV_PROJECT_ENVIRONMENT="/Users/sakibsmacbookm5/Documents/Python work/.venv"
```

Run commands from this project directory. Set the variable again in each new
terminal, or point it to your existing environment when running on another machine.
No project-local `.venv` is created. Do not delete or recreate the existing one.

The dependencies are already installed. Start the backend without network access:

```sh
uv run --offline --no-sync uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

Open **http://127.0.0.1:8000**. Stop the backend with `Ctrl+C`.
SQLite is initialized automatically at `data/analyzer.sqlite3` on startup.
Existing Phase 1/2/3 databases migrate automatically to schema version 4 while retaining
prepared jobs, chunks, and metadata. Restart the backend to load the new code.
The backend and page work even when the model server is stopped.

## Use the dashboard

Open **http://127.0.0.1:8000** after starting the backend. The existing model must
be running separately for log preparation/tokenization and AI inference.

Use the sun/moon button in the top-right corner to switch between light and dark
mode. The initial theme follows your system preference; an explicit selection is
remembered locally across reloads.

1. Drop one `.log` or `.txt` file into **Upload a log**, or use **Browse files**.
   Check the selected filename and size, then choose **Upload log**. Empty,
   unsupported or oversized files are rejected before upload; the backend also
   validates actual UTF-8 text, binary content and size while streaming to disk.
2. Wait for **Ready to analyze**, then choose **Start analysis**. The page shows
   model availability, total/completed/current chunks, completion percentage and
   elapsed run time. Rapid clicks cannot start duplicate jobs. `ready` means
   prepared; uploading never starts inference automatically.
3. Review **Security findings** after processing. Expand evidence for original
   line/chunk numbers and raw excerpts. Use severity/attack-type filters, search
   an IP/identifier, or show only incidents with multiple original evidence lines.
   **Clear filters** restores all findings. Cards paginate at 12 and expanded
   evidence loads in batches of 50 to keep the DOM small.
4. Choose **Download JSON** for the complete backend report. Filters affect only
   the displayed cards. Reports explicitly identify incomplete coverage, errors
   and limitations; an empty result never establishes that a server is secure.

The page checks status every two seconds only while preparation/inference is
active. It stops on ready/completed/partial/failed states and pauses after three
network errors. **Refresh progress** reconnects; **Refresh service status** checks
the backend/model again. A partial run retains its findings and offers **Retry
unfinished chunks**. Preparation failures require fixing the cause and reuploading.
Run elapsed time includes queueing, interruptions and retries; it is wall time,
not a measurement of model CPU time.

The current analysis ID is kept in the URL and optional localStorage, so reloading
restores its status/report without starting inference. Only the UUID is stored in
the browser. Use **Open an existing analysis** or this URL for the earlier upload:

```text
http://127.0.0.1:8000/?analysis=232a38a2-a904-4713-a9c6-576f1f3dc231
```

No frontend build or separate server is needed. All evidence and returned text use
safe text DOM rendering; log instructions/markup are never executed.

For a subsequent dependency installation into an **existing** environment, use
`uv run --locked python -c 'import app.main'` without `--no-sync`; UV installs the
locked project dependencies while preserving unrelated packages. Installation
may need internet access; normal operation does not. Use `uv add` to change
dependencies and `uv add --dev` for development dependencies. Avoid exact syncing
because this environment also contains packages belonging to other projects.

## Optional configuration

Defaults work without a `.env` file. To override them, copy `.env.example` to `.env`
and start with:

```sh
uv run --env-file .env --offline --no-sync uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATA_DIR` | `data` | Local data directory |
| `DATABASE_PATH` | `DATA_DIR/analyzer.sqlite3` | Optional SQLite file override |
| `LOG_LEVEL` | `INFO` | Application log level |
| `MODEL_BASE_URL` | `http://127.0.0.1:8080` | HTTP loopback URL only |
| `MODEL_ALIAS` | `qwen-local` | Configured model alias |
| `MODEL_HEALTH_TIMEOUT_SECONDS` | `3` | Total health-check deadline, greater than 0 and at most 30 seconds |
| `MODEL_CONTEXT_TOKENS` | `2048` | Application context cap, between 1 and 2048 |
| `MAX_UPLOAD_BYTES` | `10485760` | Maximum actual file bytes (10 MiB) |
| `TOKENIZER_TIMEOUT_SECONDS` | `30` | Complete token-count request deadline, up to 120 seconds |
| `INFERENCE_TIMEOUT_SECONDS` | `120` | Total local generation deadline, up to 600 seconds |
| `INFERENCE_MAX_ATTEMPTS` | `3` | Attempts per unfinished unit per explicit start, from 1 to 5 |
| `INFERENCE_RETRY_BACKOFF_SECONDS` | `0.25` | Exponential backoff base, from 0 to 2 seconds; each delay capped at 2 |
| `INFERENCE_RESPONSE_FORMAT` | `auto` | Try JSON schema with bounded fallback; alternatives `json_object`, `none` |
| `AUTH_FAILURE_THRESHOLD` | `5` | Distinct failed-authentication records needed in a rolling window |
| `AUTH_WINDOW_SECONDS` | `1800` | Authentication rolling/inactivity window, 30 minutes |
| `CORRELATION_LINE_WINDOW` | `10000` | Cautious record-order fallback when clocks are missing |
| `SQL_REPEAT_THRESHOLD` | `2` | Repeated SQL-pattern threshold for elevated severity |
| `SQL_WINDOW_SECONDS` | `600` | SQL-pattern correlation window |
| `SCAN_PATH_THRESHOLD` | `5` | Distinct sensitive paths needed for scanning detection |
| `SCAN_WINDOW_SECONDS` | `300` | Scanning correlation window |
| `UNAUTHORIZED_THRESHOLD` | `5` | Distinct denied-access records needed |
| `UNAUTHORIZED_WINDOW_SECONDS` | `300` | Denied-access correlation window |
| `REQUEST_RATE_THRESHOLD` | `100` | Distinct request records needed in the rate window |
| `REQUEST_RATE_WINDOW_SECONDS` | `60` | Request-rate rolling window; requires timestamps |

Relative paths resolve from the project root. Settings do not configure llama.cpp;
its process must use matching flags. `UV_PROJECT_ENVIRONMENT` is a shell variable
for UV itself; export it before running UV rather than relying on the app's `.env`.

## Start the existing model separately

Use your already installed llama.cpp and existing Qwen3.5 0.8B GGUF file. Replace
the placeholder below with the real local model path; no download is required:

```sh
llama-server \
  --model "/absolute/path/to/your/existing-model.gguf" \
  --alias qwen-local \
  --host 127.0.0.1 \
  --port 8080 \
  --ctx-size 2048 \
  --threads 2 \
  --threads-batch 2 \
  --n-gpu-layers 0 \
  --parallel 1 \
  --batch-size 128 \
  --ubatch-size 128 \
  --jinja
```

This uses CPU inference, two threads, a 2048-token context, and one inference slot.
The model plus app must fit the 4 GB evaluation budget; actual inference memory
has not been benchmarked under load. FastAPI does not start or load the model.
These flags follow the [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

Phase 3 sends generation requests to `/v1/chat/completions` with `model=qwen-local`,
`max_tokens=384`, `temperature=0.1`, and `stream=false`. Before **every** generation,
it calls `/v1/chat/completions/input_tokens` to count the complete payload, following
the [llama.cpp token-counting contract](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md#post-v1chatcompletionsinput_tokens-token-counting).
A successful health check reports server readiness, not verification of the model
file or alias. No cloud inference or automatic model download is used.

## Routes and responses

| Route | Behavior |
| --- | --- |
| `GET /` | Local status page; checks services on load and on refresh |
| `GET /health` | 200 when backend/SQLite are ready; 503 for a database failure |
| `GET /api/model/health` | 200 when llama.cpp returns `{"status":"ok"}`; 503 otherwise |
| `POST /api/analyses` | Stream and validate a multipart `file`; return 202 with its UUID and `queued` status |
| `POST /api/analyses/{id}/start` | Start or resume sequential inference for prepared evidence |
| `GET /api/analyses/{id}` | File metadata, processing status, progress counts, timestamps, and errors |
| `GET /api/analyses/{id}/chunks?limit=20&offset=0` | Paginated chunk metadata (maximum limit 100) |
| `GET /api/analyses/{id}/chunks/{chunk_id}` | One chunk's evidence, source offsets, and exact counted chat payload |
| `GET /api/analyses/{id}/findings?limit=20&offset=0` | Validated model candidates with source chunk/unit IDs |
| `GET /api/analyses/{id}/attempts?limit=20&offset=0` | Safe token/timing/retry/error diagnostics, without raw failed responses |
| `GET /api/analyses/{id}/report` | One combined, correlated JSON report with all supporting original references |
| `GET /openapi.json` | Local machine-readable API description |
| `GET /static/...` | Bundled CSS and JavaScript |

Successful backend health:

```json
{"status":"ok","database":"ok","version":"0.1.0"}
```

Successful model health:

```json
{"status":"ok","model":"qwen-local"}
```

All errors use the same envelope, for example when llama.cpp is stopped:

```json
{"error":{"code":"model_unavailable","message":"Cannot reach llama.cpp. Start the local model server."}}
```

Other model error codes are `model_not_ready`, `model_timeout`, and
`model_invalid_response`. The backend remains usable when the model is unavailable.
Request IDs are returned in `X-Request-ID` and included in UTC application logs.
The launch command disables Uvicorn's duplicate access log; application request
logs record route patterns without query strings.
Browser assets are local. Swagger/ReDoc UI is disabled because the default UI
loads assets from a CDN; the OpenAPI JSON is still available offline.

## Upload and inspect a log

The backend must be running, with the model's tokenizer available for preparation.
For example:

```sh
printf '%s\n' 'Nov  7 12:00:00 host sshd[42]: Failed password for alice from 192.0.2.4 port 22 ssh2' > /tmp/security-example.log
curl -sS -F 'file=@/tmp/security-example.log;type=text/plain' http://127.0.0.1:8000/api/analyses
```

The response is HTTP 202:

```json
{"id":"<analysis-uuid>","status":"queued"}
```

Use the returned UUID to check preparation; replace both placeholders below with
IDs returned by the preceding API calls:

```sh
curl -sS http://127.0.0.1:8000/api/analyses/ANALYSIS_ID
curl -sS 'http://127.0.0.1:8000/api/analyses/ANALYSIS_ID/chunks?limit=20&offset=0'
curl -sS http://127.0.0.1:8000/api/analyses/ANALYSIS_ID/chunks/CHUNK_ID
```

Status moves from `queued` to `processing`, then `ready` or `failed`. `ready`
means evidence and chunks are prepared, not that a security analysis was run.
Tokenizer failure is recorded on the job; the original validated file is retained.
An unavailable tokenizer does not cause a guessed token count or dropped content.

Uploads accept `.log` and `.txt` (case-insensitive), with declared MIME type
`text/plain`, `text/x-log`, or `application/octet-stream`. The actual bytes must
be UTF-8 text without binary/control characters other than tab, CR, and LF.
Empty/whitespace-only input is rejected (400), unsupported/binary input returns
415, and oversized input returns 413. Exactly one multipart `file` is accepted;
extra fields, duplicate files, and incomplete multipart are rejected.

The [streaming multipart parser](https://multipart.fastapiexpert.com/) receives
at most 64 KiB per feed. The application never reads the whole file into memory.
Actual file bytes, total envelope bytes, and headers have independent bounds,
including requests without Content-Length. Uploaded filenames become display
metadata only; mode-0600 files use server-generated UUID paths under `data/uploads/`.

## Evidence and chunk sizing

The reader processes logs sequentially in bounded 4096-character segments,
preserving UTF-8, BOM, LF/CRLF/CR, blank lines, and the final newline exactly.
Evidence contains the original 1-based `line_number`, raw text, half-open byte
and character ranges, and best-effort access/auth fields. Unknown and mixed
formats are accepted. Fields are supplementary; raw evidence stays authoritative.
Commands and instructions in logs are treated as data and are never executed.

Every chunk is built through the shared `PromptBuilder`, which includes the
system instructions, saved context, original-line/fragment labels, raw log data,
model alias, and chat-template options. The complete payload is sent to llama.cpp
for its actual templated input count. The default budget is:

```text
input ceiling = 2048 context - 384 reserved output - 64 safety = 1600 tokens
actual complete input tokens + 384 + 64 <= 2048
```

The output reservation is also saved as `max_tokens: 384`. System instructions,
saved context, JSON labels, and chat-template overhead consume the input ceiling;
1600 tokens is not an allowance for raw logs alone. A lower configured context
reduces the input ceiling. If instructions/context leave no space, the job fails.

The packer holds at most 64 entries or roughly 16 Ki characters plus one bounded
read. It first tries the complete window, then uses bounded binary searches over
whole-entry prefixes. Adjacent segments of a long line are rejoined when possible
within that window. Entries that cannot fit are split by verified character-prefix
searches, with explicit `fragment` markers and their original line/offsets. Whole
entries are preferred; chunks are conservative and need not fill every token.
Character counts only bound memory/search; they never authorize a chunk's budget.

Chunks are written to SQLite as they are prepared, with UUIDs, ordinals, boundaries,
actual token counts, status, timestamps, raw entries, and the exact counted payload.
The worker verifies contiguous byte coverage, file size, and a rolling SHA-256
against the upload before setting `ready`. There is no chunk overlap or skipped text.

Future phases can inject `PromptBuilder(system_prompt=..., saved_context=...)`
through `create_app(prompt_builder=...)`. Each job snapshots that configuration.
Later inference must reuse the exact payload or re-tokenize/rechunk after changing
the messages, saved context, model, or server template; a previous count does not
cover added instructions or newly generated context.

## Start or resume local security inference

Once preparation reports `ready`, start inference explicitly. Existing Phase 2
analysis IDs work after restarting the updated backend:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/analyses/ANALYSIS_ID/start
curl -sS http://127.0.0.1:8000/api/analyses/ANALYSIS_ID
curl -sS 'http://127.0.0.1:8000/api/analyses/ANALYSIS_ID/findings?limit=20&offset=0'
curl -sS 'http://127.0.0.1:8000/api/analyses/ANALYSIS_ID/attempts?limit=20&offset=0'
```

`/start` returns HTTP 202 with the ID and inference state. Uploading/preparing a
log alone never runs inference. Repeated starts while queued, running, or already
completed preserve existing work. After a failure or partial completion, the same
command retries only unfinished units with a fresh bounded attempt round.

After starting, the analysis's top-level `status` describes inference:
`queued`, `running`, `completed`, `partially_completed`, or `failed`.
`preparation_status` retains the original preparation state. The `inference`
object includes total/completed/failed source chunks, completed/failed units,
findings count, attempt count, and the most useful terminal error. An empty
findings list can still be a successfully completed analysis.

The single inference worker processes source chunks in order. It leaves prepared
chunks unchanged and creates smaller persisted inference units when the security
prompt needs more room. Saved context is limited to 512 characters and can be
reduced further; raw log evidence is never dropped. The exact payload is counted
again inside the inference lock immediately before every generation request.
If the live count has grown, unfinished units can split further, with a bounded
re-planning depth, while completed units stay intact. Phase 4 adds compact prior
observations and a short prior AI assessment from SQLite when relevant. It never
passes the full log history to the model. The event store, not prompt memory,
determines final cross-chunk associations.
The shared HTTP pool allows two connections so health/tokenizer checks can proceed
while the single permitted generation is running; the inference lock enforces exclusivity.

Each successful unit checkpoints its findings and completion atomically before
the next unit. Restarting the app resumes queued/interrupted runs and keeps
completed findings. A crash can require repeating an uncheckpointed model call;
it cannot insert duplicate persisted findings for that unit. Cumulative/per-round
attempt counters prevent automatic restarts from granting unlimited retries.

Connection/server errors and invalid, empty, malformed, truncated, or unverified
responses receive bounded retries with short backoff. One malformed unit does
not stop later chunks. An infrastructure outage pauses remaining work, preserving
already completed findings and reporting failed or partial completion clearly.

A timed-out/disconnected request may still be generating on llama.cpp. Before a
retry, the client checks that all local `/slots` report `is_processing=false`.
This endpoint is [enabled by default in llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md#get-slots-returns-the-current-slots-processing-state).
If idle state cannot be verified within five seconds, the job reports
`model_state_uncertain` and sends no replacement inference. Check the local server
and keep slots enabled before manually resuming. Run llama.cpp with `--parallel 1`
and the backend with `--workers 1` as documented.

## Finding contract and verification

The security prompt looks for evidence-supported brute force, SQL injection,
scanning, unauthorized access, and unusual request rates. It distinguishes ordinary
application errors, treats embedded log instructions as untrusted data, prohibits
invented entities/citations, and requests concise JSON with no confirmed-attack claims.

The response contract is:

```json
{
  "findings": [
    {
      "attack_type": "Possible brute-force attack",
      "severity": "High",
      "identifier": "192.0.2.4",
      "evidence": [{"line": 1, "excerpt": "Failed login for alice from 192.0.2.4"}],
      "reason": "Repeated authentication failures.",
      "suggested_action": "Investigate and rate-limit the source.",
      "confidence": "possible"
    }
  ]
}
```

This illustrates the contract, not a hardcoded application finding. Strict Pydantic
models require the fields, supported severities, nonempty reasons/actions, and
bounded lengths. Confidence is restricted to `possible`. Evidence lines must belong
to the actual inference unit, excerpts must match the supplied original line range
exactly, and identifiers must occur in those excerpts. Raw byte ranges are checked
against the uploaded file both before generation and before accepting findings.
Invalid findings are rejected as a response and never stored in the findings table.

Schema-constrained output is requested when supported, with bounded fallback to
plain JSON output if llama.cpp rejects format options. Strict parsing is tried
first, then optional surrounding code-fence removal and cautious complete-object
extraction. Duplicate keys, ambiguous multiple objects, truncated objects, and
non-finite numbers are rejected. Failed output is not sent back as instructions.

Accepted candidates are labeled `evidence_verified`. This validates their citations,
not the truth of the model's interpretation. A small local model can miss attacks
or produce false positives; its findings remain reviewable suspicions. Empty output
`{"findings":[]}` is valid and is preserved without inventing results.

Attempt history stores response hashes/byte counts, request hashes, HTTP/error
codes, JSON recovery mode, actual tokens, and timing. Raw failed responses and
exception content are not retained. Findings and required quoted evidence are
stored only after validation; APIs are paginated to keep memory bounded.

## Combined security report

After restarting the updated backend, request a report for a new or existing
analysis. This example uses the analysis ID from the uploaded project log:

```sh
curl -sS http://127.0.0.1:8000/api/analyses/232a38a2-a904-4713-a9c6-576f1f3dc231/report
```

To save the full JSON locally:

```sh
curl -sS http://127.0.0.1:8000/api/analyses/232a38a2-a904-4713-a9c6-576f1f3dc231/report \
  -o data/security-report.json
```

The report contains analysis ID/status/filename, completed AI chunks, indexed
chunks, total merged findings, severity counts, related identifiers, incidents,
all original evidence references, short reasons/actions, limitations, and errors.
`total_findings` counts merged incidents; `/findings` continues to expose raw
validated model candidates for inspection. `processed_chunks` counts completed
AI source chunks; `indexed_chunks` shows deterministic event coverage.

You can request a deterministic report before starting inference. It explicitly
states that AI has not run. A report during running/partial processing preserves
completed findings and marks `report_complete: false`. A final report becomes
complete only after preparation/indexing and inference finish at the same evidence
revision. If evidence arrives during a build, request the report again for a fresh
snapshot; the response discloses that lag.

Events are indexed when prepared chunks are saved. Existing Phase 2/3 analyses
are backfilled one bounded stored chunk/finding at a time, without regenerating
completed AI output. Each observed event retains source chunk/line, literal
timestamp and clock kind, source IP/identifier, account, target/path, HTTP status,
normalized type, and a bounded original quote. Missing fields stay null.

The parser recognizes common access/auth/SSH logs, explicit security-detector
messages, and simple JSON fields. It records failed/successful authentication,
denials, SQL payload patterns, sensitive-path probes, and HTTP records used for
rate counts. Access-log request text cannot override its remote address/user.
An HTTP 200 on `/login` is not proof of successful authentication. Generic
404/500 responses and ordinary SQL debug errors are not enough to label an attack.

Exact duplicate records share one event but retain every original reference.
Reindexing, retries, and AI citations do not inflate counters. Identical genuine
requests without distinguishing timestamp/request fields can be conservatively
undercounted; the report includes this limitation. Evidence references are
deduplicated independently of model findings and incident categories.

### How distant chunks are linked

Authentication, SQL patterns, and denials group by observed source/identifier,
account, and normalized target. SQL targets omit query strings for grouping while
the evidence retains the actual request. Scanning/rate patterns group at the
source level across paths. Different sources, accounts, targets, and separate
activity episodes remain distinct.

Detection uses **rolling windows**, rather than fixed wall-clock buckets or an
all-history counter. Episodes split after an inactivity gap exceeding the rule's
window, a backward clock, an incompatible clock kind, or a new failure burst after
an associated success. Bounded timestamp/path counters hold only enough recent
marks to evaluate the threshold; every source reference stays in SQLite.

For example, three failures in source chunk 1 and two more in chunk 5, followed
by an explicit successful authentication in chunk 10 for the same source/account,
produce one combined incident if the five preceding failures fit the configured
30-minute window before success. The report retains evidence from all three
chunks even if none of that history fits in the current AI prompt. Success does
not establish that the account was compromised.

Offset-aware clocks compare actual instants. Naive/yearless clocks are compared
as relative clocks only; no timezone or year is invented. Missing/unsupported
timestamps use the configured original-line window cautiously and never establish
elapsed time. Request-rate findings require timestamps. Clock limitations are
included in the output.

### Merging and severity

| Evidence | Severity rule |
| --- | --- |
| Threshold authentication failures without associated success | Medium |
| Threshold failures followed by success, with known source/account and offset-aware clock | High; compromise remains possible, never confirmed |
| Missing/naive/yearless clock or weaker authentication attribution | Medium |
| Explicit SQL-injection request/detector pattern | Medium |
| Repeated SQL patterns meeting the configured threshold with an offset-aware clock | High |
| Sensitive-path scanning or repeated denied access meeting rolling thresholds | Medium |
| Request-rate threshold met with comparable timestamps | Low; legitimate high traffic remains possible |
| Supported model-only assessments below deterministic thresholds | Low/Medium, capped at Medium |

No rule automatically asserts Critical or confirmed exploitation. Deterministic
severity takes precedence over a model's label; merged model-only severity uses
the highest supported level under its cap, independently of arrival order.

Validated AI candidates join the appropriate category/scope/episode through shared
observed-event references. Repeated SQL findings across chunks therefore become
one incident with combined evidence and AI IDs. AI labels supported only by generic
errors or an unsupported category remain in `/findings` but are excluded from
final incidents, with an explanatory omission count. Related rate/denial signals
can merge into one unambiguous overlapping security incident; the engine never
chooses arbitrarily between separate accounts or targets.

`confirmed_log_events` describes statements present in the log, not confirmed
real-world attacks. Every incident has `risk_status: inferred_possible`. Final
titles/reasons follow the documented rules rather than repeating an unsupported
model claim of confirmed compromise.

### Compact memory and report consistency

Later inference units query only relevant earlier source/account/target records,
within the applicable clock/line window. The saved context contains bounded counts,
line references, and at most a short previous AI assessment labeled possible.
It is capped at 512 characters; whole summaries can be dropped to preserve the
2048-token budget. Future evidence/findings cannot leak backward into a resumed
earlier unit. SQLite retains authoritative history regardless of prompt space.

Correlation is cached by evidence revision and rule hash. Builds read a consistent
SQLite snapshot and publish atomically, retaining stable public incident IDs when
new AI support arrives. Derived writes commit in bounded batches so inference can
checkpoint. The API streams incident evidence instead of building an all-evidence
list in RAM. The sequential read stream explicitly supports Starlette resuming it
on different worker threads.

## Processing and remaining limits

One in-process worker claims jobs from SQLite and performs preparation sequentially.
At restart, interrupted preparation is requeued and its partial chunks are rebuilt
from the original file. Interrupted uploads fail and their temporary files are
cleaned up. Keep the backend at **one worker**; multiple processes sharing this
recovery mechanism are not supported.

The reader supports UTF-8 text, not UTF-16, compressed logs, or arbitrary binary formats.
ANSI escape/control sequences are rejected. Field extraction is best-effort, including
for fragmented entries; all original evidence is retained for later validation.
Extremely compressible long lines can be fragmented at the bounded memory window
even when a larger window might fit the token limit. Token-search packing prioritizes
verified safety and coverage over globally optimal chunk utilization.

Preparation failures require fixing the problem and reuploading; inference failures
can resume with `/start`. There is no aggregate disk quota, retention/deletion UI,
or automatic cleanup of completed jobs. Raw files, evidence, and exact
payloads occupy local disk until manually managed; do not remove files belonging
to active jobs. The 4 GB target has not been benchmarked under concurrent load.

## Tests

With `UV_PROJECT_ENVIRONMENT` exported as above:

```sh
uv run --offline --no-sync pytest -q
```

The default suite uses temporary databases and fake tokenizers, so it requires
neither a running model nor internet access. It covers configuration, loopback
restrictions, migration, persistence/rollback, upload validation and streaming,
original line numbers, byte-for-byte coverage, long-line fragments, exact prompt
budget checks, a roughly 20,000-token log, and restart recovery alongside Phase 1.
Phase 3 tests additionally cover JSON recovery/schema/evidence rejection, prompt
injection as data, sequential execution, safe timeout retries, partial findings,
idempotent resume, migration, live token-budget rejection, and persistent re-planning.

Phase 5 adds API checks for the page's configured upload limit, local assets,
safe rendering contract, exact running chunk ordinal during retries, and streamed
JSON download matching the combined report. `?download=true` adds a safe attachment
filename to the existing report endpoint; it does not change report content.

Run the optional end-to-end dashboard tests with your **already installed** Chrome:

```sh
RUN_BROWSER_TESTS=1 uv run --offline --no-sync pytest -q tests/test_dashboard_browser.py
```

These tests use temporary storage, a loopback FastAPI server and a fake local
tokenizer/model. They open real headless Chrome to check upload/start/progress,
duplicate-click prevention, reports and expandable evidence, filters, complete
JSON downloads, desktop/mobile layouts, reload recovery, terminal polling stop,
invalid/empty/oversized/binary inputs, unavailable-model handling and partial-run
retry. Embedded HTML in log evidence must display as text without executing.
No test installs a browser, Node, package or model. Set `CHROME_PATH` if your existing
Chrome/Chromium executable is elsewhere. The macOS default is
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`.
Add `PHASE5_SCREENSHOT_DIR=data/phase5-preview` to save browser QA screenshots
of synthetic data. The real model/tokenizer checks below remain separate opt-ins.

Run the real-tokenizer integration checks separately with your existing llama.cpp:

```sh
RUN_MODEL_INTEGRATION=1 uv run --offline --no-sync pytest -q -m integration
```

These tests calibrate a roughly 20,000-token fixture using a small real-tokenizer
sample, then prepare a multiline log and a long single line through the API. They
independently recount every saved payload and verify its budget and rolling evidence
hash. No model download or generation is performed. The shared environment's
unrelated ML packages are not imported by this application.

The separate opt-in inference test makes a real local Qwen call on a small synthetic
authentication log and validates its output through the normal API/checkpoint path:

```sh
RUN_INFERENCE_INTEGRATION=1 uv run --offline --no-sync pytest -q -s tests/test_inference_integration.py
```

It skips if the separately started llama.cpp server is unavailable. Set
`PHASE3_SAMPLE_PATH=data/phase3-validated-sample.json` to save the actual validated
result. The implementation check produced `{"findings": []}`; no artificial
findings were added. A validated sample is an observation, not a model accuracy benchmark.

Phase 4 correlation/parser/report tests are included in the default suite. The
stream-written fixture places three failures at lines 100–102, two more at
4999–5000, and a successful authentication at line 9000. Explicit source boundaries
put them in source chunks 1, 5, and 10; this isolates correlation from tokenizer
packing. The regular inference worker still splits/recounts those source chunks
before every mocked generation call. A separate test covers normal API uploads.

Save the actual demonstration report (the model is mocked; correlations are real):

```sh
PHASE4_REPORT_PATH=data/phase4-demo-report.json uv run --offline --no-sync pytest -q \
  tests/test_correlation.py::test_distant_chunk_1_5_10_authentication_is_one_final_finding
```

The report's one High-severity incident contains all six original evidence lines
across the three distant source chunks. Additional tests cover SQL merging,
different attackers/accounts/targets/windows, missing/backward clocks, duplicates,
ordinary-error exclusions, compact-context relevance, legacy backfill, partial AI
failures, stable report identities, and cross-thread streaming.

See [AGENTS.md](AGENTS.md) for the full constraints and architectural decisions.
