"use strict";

// Presentation only. Detection, queueing, retries and correlation stay in Python.
(() => {
  const $ = (id) => document.getElementById(id);
  function renderTheme() {
    const light = document.documentElement.dataset.theme === "light";
    $("theme-toggle").setAttribute("aria-pressed", String(light));
    $("theme-toggle").title = light ? "Switch to dark mode" : "Switch to light mode";
  }
  $("theme-toggle").addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("local-ai-theme", theme); } catch { /* The switch still works when storage is disabled. */ }
    renderTheme();
  });
  renderTheme();
  const TERMINAL = new Set(["completed", "partially_completed", "failed"]);
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const SEVERITIES = ["Critical", "High", "Medium", "Low"];
  const TYPES = { authentication: "Authentication", sql_injection: "SQL injection", scanning: "Scanning", unauthorized: "Unauthorized access", request_rate: "Request rate" };
  const PAGE_SIZE = 12;
  const state = { file: null, job: null, id: null, report: null, epoch: 0, timer: null,
    uploadBusy: false, startBusy: false, statusBusy: false, reportBusy: false, healthBusy: false,
    backend: false, model: false, lastHealth: 0, pollErrors: 0, page: 0, matches: [], reportPromise: null };

  function message(id, text = "") {
    $(id).textContent = text;
    $(id).hidden = !text;
  }
  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }
  function sizeLabel(size) {
    return size < 1024 ? `${size} bytes` : size < 1048576 ? `${(size / 1024).toFixed(1)} KiB` : `${(size / 1048576).toFixed(2)} MiB`;
  }
  function busy(button, active, label) {
    button.disabled = active;
    button.setAttribute("aria-busy", String(active));
    button.textContent = label;
  }
  function apiPath(suffix = "") { return `/api/analyses/${encodeURIComponent(state.id)}${suffix}`; }
  function isCurrent(epoch) { return epoch === state.epoch; }
  function canStart() {
    return state.job?.preparation_status === "ready" && !["queued", "running", "completed"].includes(state.job?.inference?.status);
  }
  function updateButtons() {
    $("start-analysis").disabled = !canStart() || state.startBusy || state.uploadBusy || state.statusBusy || state.healthBusy || !state.model || !state.backend;
    $("start-analysis").textContent = state.startBusy ? "Starting…" : state.job?.inference && TERMINAL.has(state.job.status) && state.job.status !== "completed" ? "Retry unfinished chunks →" : "Start analysis →";
    $("upload-button").disabled = state.uploadBusy || state.startBusy;
    $("browse-file").disabled = state.uploadBusy;
    $("remove-file").disabled = state.uploadBusy;
    $("open-analysis").disabled = state.uploadBusy || state.startBusy;
    $("refresh-analysis").disabled = !state.id || state.statusBusy || state.startBusy;
    $("refresh-report").disabled = !state.job || state.reportBusy || state.job.preparation_status !== "ready" && state.job.status !== "failed";
    $("download-report").setAttribute("aria-disabled", String(!state.report));
  }

  async function request(url, options = {}, timeoutMs = 20000) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json", ...options.headers }, signal: controller.signal });
      let body;
      try { body = await response.json(); } catch { throw new Error("The backend returned an incomplete or unreadable response. Try refreshing."); }
      if (!response.ok) {
        const error = new Error(typeof body.error?.message === "string" ? body.error.message : `The request failed (HTTP ${response.status}).`);
        error.status = response.status;
        throw error;
      }
      return body;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The request timed out. Check progress before trying again.");
      if (error instanceof TypeError) throw new Error("Cannot reach the backend. Check that the application is running, then refresh.");
      throw error;
    } finally { window.clearTimeout(timeout); }
  }

  async function refreshHealth() {
    if (state.healthBusy) return;
    state.healthBusy = true;
    updateButtons();
    $("refresh-status").disabled = true;
    $("refresh-status").setAttribute("aria-busy", "true");
    const errors = [];
    try {
      await Promise.all([ ["backend", "/health"], ["model", "/api/model/health"] ].map(async ([service, url]) => {
        const badge = $(`${service}-status`);
        badge.dataset.state = "checking";
        badge.textContent = `${service === "backend" ? "Backend" : "Model"} · Checking`;
        try {
          const body = await request(url, {}, 35000);
          if (body.status !== "ok") throw new Error("The service is not ready.");
          state[service] = true;
          badge.dataset.state = "ok";
          badge.textContent = `${service === "backend" ? "Backend" : "Model"} · Connected`;
        } catch (error) {
          state[service] = false;
          badge.dataset.state = "error";
          badge.textContent = `${service === "backend" ? "Backend" : "Model"} · Unavailable`;
          errors.push(service === "model" ? "Local AI server unavailable. Start your existing llama.cpp server, then refresh service status. Existing reports remain available." : error.message);
        }
      }));
      message("service-error", errors.join(" "));
      state.lastHealth = Date.now();
    } finally {
      state.healthBusy = false;
      $("refresh-status").disabled = false;
      $("refresh-status").setAttribute("aria-busy", "false");
      updateButtons();
    }
  }

  function selectFile(files) {
    if (state.uploadBusy) return;
    state.file = null;
    $("selected-file").hidden = true;
    $("log-file").value = "";
    let error = "";
    const file = files[0];
    if (files.length > 1) error = "Choose one log file at a time.";
    else if (!file) error = "Select a .log or .txt file first.";
    else if (!/\.(log|txt)$/i.test(file.name)) error = "Unsupported file. Choose a .log or .txt file.";
    else if (file.size === 0) error = "This file is empty. Choose a log containing text.";
    else if (file.size > Number(document.body.dataset.maxUploadBytes)) error = `This file is too large. The limit is ${sizeLabel(Number(document.body.dataset.maxUploadBytes))}.`;
    if (!error) {
      state.file = file;
      $("selected-name").textContent = file.name;
      $("selected-name").title = file.name;
      $("selected-size").textContent = sizeLabel(file.size);
      $("selected-file").hidden = false;
    }
    message("upload-error", error);
    updateButtons();
  }

  function stopPolling() {
    window.clearTimeout(state.timer);
    state.timer = null;
  }
  function activate(id) {
    stopPolling();
    state.epoch += 1;
    state.id = id.toLowerCase();
    state.job = null;
    state.report = null;
    state.statusBusy = false;
    state.reportBusy = false;
    state.reportPromise = null;
    state.pollErrors = 0;
    state.page = 0;
    $("filter-search").value = "";
    $("filter-severity").value = "";
    $("filter-type").value = "";
    $("filter-multiple").checked = false;
    $("analysis-id").value = state.id;
    $("download-report").removeAttribute("href");
    message("analysis-error");
    message("report-error");
    message("export-status");
    message("open-error");
    resetReport();
    renderStatus();
    updateButtons();
    return state.epoch;
  }
  function remember() {
    try { localStorage.setItem("local-ai-analysis-id", state.id); } catch { /* Storage can be disabled. */ }
    const url = new URL(window.location.href);
    url.searchParams.set("analysis", state.id);
    window.history.replaceState(null, "", url);
  }
  function duration(seconds) {
    const value = Math.max(0, Math.floor(seconds));
    return value < 60 ? `${value}s` : value < 3600 ? `${Math.floor(value / 60)}m ${value % 60}s` : `${Math.floor(value / 3600)}h ${Math.floor(value % 3600 / 60)}m`;
  }
  function renderStatus() {
    const job = state.job;
    const run = job?.inference;
    const active = Boolean(job && !TERMINAL.has(job.status) && job.status !== "ready");
    const labels = { uploading: "Uploading", queued: run ? "Analysis queued" : "Preparation queued", processing: "Preparing log", ready: "Ready to analyze", running: "Analyzing", completed: "Completed", partially_completed: "Partially completed", failed: "Failed" };
    $("analysis-status").textContent = job ? labels[job.status] || job.status : state.id ? "Loading analysis…" : "Awaiting upload";
    $("analysis-status").dataset.state = job?.status === "completed" || job?.status === "ready" ? "ok" : job && TERMINAL.has(job.status) ? "warning" : active ? "running" : "idle";
    $("analysis-filename").textContent = job?.filename || (state.id ? "Loading analysis…" : "No log selected for analysis");
    $("analysis-filename").title = job?.filename || "";
    $("analysis-meta").textContent = job ? `${sizeLabel(job.size_bytes)} · ${job.total_lines.toLocaleString()} original lines · ID ${job.id}` : state.id || "Upload a file to prepare its original evidence.";
    const total = run?.total_chunks ?? job?.total_chunks ?? 0;
    const completed = run?.completed_chunks ?? 0;
    const percent = total ? Math.min(100, Math.floor(completed / total * 100)) : 0;
    $("total-chunks").textContent = job ? total.toLocaleString() : "—";
    $("completed-chunks").textContent = job ? completed.toLocaleString() : "—";
    $("current-chunk").textContent = run?.current_chunk ?? "—";
    $("progress-percent").textContent = run ? `${percent}%` : "—";
    $("analysis-progress").value = percent;
    if (job && !run && ["queued", "processing"].includes(job.status)) $("analysis-progress").removeAttribute("value");
    $("progress-label").textContent = run ? `${completed} of ${total} chunks completed${run.failed_chunks ? ` · ${run.failed_chunks} failed` : ""}` : job?.status === "ready" ? "Log prepared. Ready for local AI analysis." : active ? "Preparing and tokenizing the original log…" : job?.status === "failed" ? "Log preparation could not complete." : "Ready when you are";
    const start = run && Date.parse(run.created_at);
    const end = run && (TERMINAL.has(run.status) ? Date.parse(run.updated_at) : Date.now());
    $("elapsed-time").textContent = start && Number.isFinite(end) ? duration((end - start) / 1000) : "—";
    $("polling-note").textContent = active ? "Updates every 2 seconds" : job?.status === "ready" ? "Waiting for you to start" : job && TERMINAL.has(job.status) ? "Automatic updates stopped" : "No analysis running";
    const hints = { ready: "Preparation is complete. Start analysis to build the combined local AI security report.", completed: "Analysis complete. Review the combined findings and their original evidence below.", partially_completed: "Some chunks did not complete. Available findings are preserved; retry only the unfinished work.", failed: run ? "Completed checkpoints are preserved. Check the error and local model before retrying unfinished chunks." : "Fix the upload or model connection problem, then upload the log again." };
    $("analysis-hint").textContent = hints[job?.status] || "Chunks are analyzed sequentially, then related evidence is linked across the full log.";
    const error = job?.error?.message || (run?.failed_chunks ? `${run.failed_chunks} chunk(s) failed. Available evidence is preserved.` : "");
    message("analysis-error", error);
    updateButtons();
  }
  async function poll(epoch = state.epoch) {
    if (!state.id || !isCurrent(epoch) || state.statusBusy) return;
    stopPolling();
    state.statusBusy = true;
    updateButtons();
    let again = false;
    try {
      const job = await request(apiPath());
      if (!isCurrent(epoch)) return;
      state.job = job;
      state.pollErrors = 0;
      remember();
      renderStatus();
      if (TERMINAL.has(job.status)) {
        await loadReport(true);
        if (job.status !== "completed") void refreshHealth();
      } else again = job.status !== "ready";
      if (again && Date.now() - state.lastHealth > 15000) void refreshHealth();
    } catch (error) {
      if (!isCurrent(epoch)) return;
      state.pollErrors += 1;
      message("analysis-error", error.message);
      again = error.status !== 404 && error.status !== 422 && state.pollErrors < 3;
      $("polling-note").textContent = again ? "Connection interrupted · Retrying" : "Updates paused · Refresh to reconnect";
      if (!again && error.status === 404) { try { localStorage.removeItem("local-ai-analysis-id"); } catch { /* Optional persistence. */ } }
    } finally {
      if (isCurrent(epoch)) {
        state.statusBusy = false;
        updateButtons();
        if (again) state.timer = window.setTimeout(() => void poll(epoch), state.pollErrors ? 4000 : 2000);
      }
    }
  }

  async function upload(event) {
    event.preventDefault();
    if (state.uploadBusy || state.startBusy) return;
    if (!state.file) { message("upload-error", "Select a .log or .txt file first."); $("browse-file").focus(); return; }
    state.uploadBusy = true;
    busy($("upload-button"), true, "Uploading…");
    updateButtons();
    message("upload-error");
    try {
      const form = new FormData();
      form.append("file", state.file, state.file.name);
      const body = await request("/api/analyses", { method: "POST", body: form }, 120000);
      if (!UUID.test(body.id)) throw new Error("The backend did not return a valid analysis ID.");
      const epoch = activate(body.id);
      state.file = null;
      $("selected-file").hidden = true;
      await poll(epoch);
    } catch (error) { message("upload-error", error.message); }
    finally {
      state.uploadBusy = false;
      busy($("upload-button"), false, "Upload log ↑");
      updateButtons();
    }
  }
  async function start() {
    if (state.startBusy || state.uploadBusy || state.statusBusy || state.healthBusy || !canStart()) return;
    if (!state.model || !state.backend) { message("analysis-error", "Check the backend and local model connection before starting."); return; }
    state.startBusy = true;
    const epoch = state.epoch;
    stopPolling();
    $("start-analysis").setAttribute("aria-busy", "true");
    updateButtons();
    message("analysis-error");
    let errorMessage = "";
    try {
      if (Date.now() - state.lastHealth > 15000) await refreshHealth();
      if (!state.model || !state.backend) throw new Error("The backend or local model is unavailable. Refresh service status after reconnecting it.");
      await request(apiPath("/start"), { method: "POST" });
      if (!isCurrent(epoch)) return;
      state.report = null;
      resetReport();
      // Reconcile with durable backend state even if the POST response was lost.
    } catch (error) { errorMessage = error.message; }
    finally {
      if (isCurrent(epoch)) {
        state.startBusy = false;
        $("start-analysis").setAttribute("aria-busy", "false");
        await poll(epoch);
        if (errorMessage) message("analysis-error", errorMessage);
        updateButtons();
      }
    }
  }

  function resetReport() {
    state.page = 0;
    state.matches = [];
    $("findings-list").replaceChildren();
    for (const severity of ["total", "critical", "high", "medium", "low"]) $(`count-${severity}`).textContent = "—";
    $("report-badge").textContent = state.job?.inference ? "Awaiting report" : "No report yet";
    $("report-badge").dataset.state = "idle";
    $("report-notes").hidden = true;
    $("notes-list").replaceChildren();
    $("pagination").hidden = true;
    $("empty-state").hidden = false;
    $("empty-title").textContent = state.id ? "Your report will appear here." : "A clear view starts with a log.";
    $("empty-message").textContent = "Upload a .log or .txt file, start analysis, and review the connected evidence here.";
    $("results-count").textContent = "Your findings will appear here";
    $("download-report").removeAttribute("href");
    $("download-report").setAttribute("aria-disabled", "true");
    for (const control of $("filters").querySelectorAll("input, select")) control.disabled = true;
    $("clear-filters").disabled = true;
  }
  async function loadReport(fresh = false) {
    if (!state.id || !state.job) return;
    const epoch = state.epoch;
    if (state.reportBusy) {
      await state.reportPromise;
      if (fresh === true && isCurrent(epoch)) return loadReport();
      return;
    }
    const path = apiPath("/report");
    state.reportBusy = true;
    busy($("refresh-report"), true, "Loading report…");
    message("report-error");
    if (!state.report) {
      $("report-badge").textContent = "Building report…";
      $("empty-title").textContent = "Connecting the evidence…";
      $("empty-message").textContent = "Reading the combined report from the local database.";
    }
    state.reportPromise = (async () => {
      try {
        const report = await request(path, {}, 120000);
        if (!isCurrent(epoch)) return;
        if (!Array.isArray(report.incidents) || !report.finding_counts_by_severity) throw new Error("The report response is missing required fields. Try refreshing the report.");
        state.report = report;
        renderReport();
      } catch (error) {
        if (!isCurrent(epoch)) return;
        message("report-error", error.message);
        if (!state.report) {
          $("report-badge").textContent = "Report unavailable";
          $("empty-title").textContent = "The report could not be loaded.";
          $("empty-message").textContent = "Check the connection and use Refresh report to try again. Saved backend findings are preserved.";
        }
      } finally {
        if (isCurrent(epoch)) {
          state.reportBusy = false;
          busy($("refresh-report"), false, "Refresh report");
          updateButtons();
        }
      }
    })();
    return state.reportPromise;
  }
  function renderReport() {
    const report = state.report;
    $("count-total").textContent = Number(report.total_findings).toLocaleString();
    for (const severity of SEVERITIES) $(`count-${severity.toLowerCase()}`).textContent = Number(report.finding_counts_by_severity[severity] || 0).toLocaleString();
    $("report-badge").textContent = report.report_complete ? "Final report" : "Partial report";
    $("report-badge").dataset.state = report.report_complete ? "ok" : "warning";
    const notes = [...(report.limitations || [])];
    if (!report.report_complete) notes.unshift("Analysis is incomplete. This report covers available evidence and may change when unfinished processing completes.");
    for (const error of report.analysis_errors || []) notes.unshift(`${error.stage || "Processing"}: ${error.message || error.code || "Chunk processing failed"}${error.count ? ` (${error.count})` : ""}`);
    $("notes-list").replaceChildren(...notes.map((text) => node("li", "", text)));
    $("report-notes").hidden = !notes.length;
    $("notes-title").textContent = `Analysis notes & limitations (${notes.length})`;
    if (report.analysis_errors?.length) message("report-error", "Some processing did not complete. Available findings are shown below. Open analysis notes for details.");
    const previousType = $("filter-type").value;
    const categories = new Set(report.incidents.map((finding) => finding.category || finding.title));
    $("filter-type").replaceChildren(node("option", "", "All attack types"));
    $("filter-type").firstChild.value = "";
    for (const category of [...categories].sort()) {
      const option = node("option", "", TYPES[category] || category);
      option.value = category;
      $("filter-type").append(option);
    }
    $("filter-type").value = categories.has(previousType) ? previousType : "";
    for (const control of $("filters").querySelectorAll("input, select")) control.disabled = false;
    $("clear-filters").disabled = false;
    $("download-report").href = `${apiPath("/report")}?download=true`;
    $("download-report").download = `security-report-${state.id}.json`;
    applyFilters();
    updateButtons();
  }
  function multipleLines(evidence = []) {
    if (evidence.length < 2) return false;
    return evidence.some((entry) => entry.line !== evidence[0].line);
  }
  function applyFilters() {
    if (!state.report) return;
    const severity = $("filter-severity").value;
    const type = $("filter-type").value;
    const query = $("filter-search").value.trim().toLowerCase();
    const multiple = $("filter-multiple").checked;
    state.matches = state.report.incidents.filter((finding) => (!severity || finding.severity === severity)
      && (!type || (finding.category || finding.title) === type)
      && (!query || String(finding.identifier || "").toLowerCase().includes(query))
      && (!multiple || multipleLines(finding.evidence)));
    state.page = 0;
    renderFindings();
  }
  function fact(container, label, value) {
    if (value === undefined || value === null || value === "") return;
    const item = node("span");
    item.append(node("b", "", label), document.createTextNode(String(value)));
    container.append(item);
  }
  function findingCard(finding) {
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "Low";
    const card = node("article", `finding-card ${severity.toLowerCase()}`);
    const heading = node("div", "finding-heading");
    const title = node("div");
    title.append(node("h3", "", finding.title || "Security observation"), node("p", "risk-label", "Possible risk · Review supporting evidence"));
    heading.append(title, node("span", "severity-badge", severity));
    const facts = node("div", "finding-facts");
    fact(facts, "Source", finding.identifier || "Not recorded");
    fact(facts, "Account", finding.username);
    fact(facts, "Target", finding.target);
    fact(facts, "Time", finding.timestamp_start && finding.timestamp_end && finding.timestamp_start !== finding.timestamp_end ? `${finding.timestamp_start} → ${finding.timestamp_end}` : finding.timestamp_start);
    if (finding.time_basis === "line_order_only") fact(facts, "Order", "Original lines only · No comparable timestamps");
    const action = node("div", "finding-action");
    action.append(node("strong", "", "Suggested action"), document.createTextNode(finding.suggested_action || "Review the source evidence."));
    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    const details = node("details", "evidence-details");
    details.append(node("summary", "", `View original evidence (${evidence.length} reference${evidence.length === 1 ? "" : "s"})`));
    // Evidence is populated only on expansion, at most 50 rows per click.
    let loaded = 0;
    const evidenceBody = node("div");
    const more = node("button", "button secondary compact evidence-more", "Show more evidence");
    more.type = "button";
    function nextEvidence() {
      const end = Math.min(loaded + 50, evidence.length);
      const fragment = document.createDocumentFragment();
      for (; loaded < end; loaded += 1) {
        const entry = evidence[loaded];
        const row = node("div", "evidence-row");
        const ref = node("div", "evidence-ref");
        ref.append(node("strong", "", `Line ${entry.line}`));
        if (entry.chunk_ordinal) ref.append(node("span", "", `Chunk ${entry.chunk_ordinal}`));
        if (entry.start_char) ref.append(node("span", "", `Character ${entry.start_char}`));
        row.append(ref, node("pre", "", entry.excerpt));
        fragment.append(row);
      }
      evidenceBody.append(fragment);
      more.hidden = loaded >= evidence.length;
      more.textContent = `Show more evidence (${evidence.length - loaded} remaining)`;
    }
    more.addEventListener("click", nextEvidence);
    details.addEventListener("toggle", () => { if (details.open && !loaded) nextEvidence(); });
    details.append(evidenceBody, more);
    more.hidden = true;
    card.append(heading, facts, node("p", "finding-reason", finding.reason), action, details);
    return card;
  }
  function renderFindings() {
    const all = state.report.incidents.length;
    const matched = state.matches.length;
    const start = state.page * PAGE_SIZE;
    const fragment = document.createDocumentFragment();
    for (const finding of state.matches.slice(start, start + PAGE_SIZE)) fragment.append(findingCard(finding));
    $("findings-list").replaceChildren(fragment);
    $("empty-state").hidden = matched > 0;
    $("results-count").textContent = matched ? `Showing ${start + 1}–${Math.min(start + PAGE_SIZE, matched)} of ${matched} findings${matched !== all ? ` (${all} total)` : ""}` : "0 findings shown";
    if (!matched) {
      $("empty-title").textContent = all ? "No findings match these filters." : "No suspicious activity was identified in the analyzed data.";
      $("empty-message").textContent = all ? "Try another source, attack type, or severity, or clear your filters." : state.report.report_complete ? "Review the analysis notes for coverage and limitations. This does not establish that the server is secure." : "This report is incomplete. Remaining chunks or failed analysis may change the result; review the analysis notes.";
    }
    const pages = Math.ceil(matched / PAGE_SIZE);
    $("pagination").hidden = pages <= 1;
    $("page-label").textContent = `Page ${state.page + 1} of ${pages}`;
    $("previous-page").disabled = state.page === 0;
    $("next-page").disabled = state.page + 1 >= pages;
  }

  $("browse-file").addEventListener("click", () => $("log-file").click());
  $("log-file").addEventListener("change", (event) => selectFile([...event.target.files]));
  $("remove-file").addEventListener("click", () => { state.file = null; $("selected-file").hidden = true; message("upload-error"); updateButtons(); });
  $("upload-form").addEventListener("submit", upload);
  const dropzone = $("dropzone");
  let dragDepth = 0;
  dropzone.addEventListener("dragenter", (event) => { event.preventDefault(); dragDepth += 1; if (!state.uploadBusy) dropzone.classList.add("is-dragover"); });
  dropzone.addEventListener("dragover", (event) => event.preventDefault());
  dropzone.addEventListener("dragleave", (event) => { event.preventDefault(); dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dropzone.classList.remove("is-dragover"); });
  dropzone.addEventListener("drop", (event) => { event.preventDefault(); dragDepth = 0; dropzone.classList.remove("is-dragover"); selectFile([...event.dataTransfer.files]); });
  // Prevent a missed drop from navigating away to an untrusted local file.
  window.addEventListener("dragover", (event) => event.preventDefault());
  window.addEventListener("drop", (event) => event.preventDefault());
  $("start-analysis").addEventListener("click", start);
  $("refresh-analysis").addEventListener("click", () => void poll());
  $("refresh-status").addEventListener("click", refreshHealth);
  $("refresh-report").addEventListener("click", loadReport);
  $("open-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.uploadBusy || state.startBusy) return;
    const id = $("analysis-id").value.trim();
    if (!UUID.test(id)) { message("open-error", "Enter a valid analysis UUID."); return; }
    const epoch = activate(id);
    await poll(epoch);
  });
  $("download-report").addEventListener("click", (event) => {
    if (!state.report) { event.preventDefault(); return; }
    message("export-status", "Download requested. Your browser will save the complete backend report, including findings hidden by filters.");
  });
  for (const id of ["filter-severity", "filter-type", "filter-multiple"]) $(id).addEventListener("change", applyFilters);
  let searchTimer;
  $("filter-search").addEventListener("input", () => { window.clearTimeout(searchTimer); searchTimer = window.setTimeout(applyFilters, 150); });
  $("clear-filters").addEventListener("click", () => {
    $("filter-search").value = "";
    $("filter-severity").value = "";
    $("filter-type").value = "";
    $("filter-multiple").checked = false;
    applyFilters();
  });
  $("previous-page").addEventListener("click", () => { if (state.page > 0) { state.page -= 1; renderFindings(); } });
  $("next-page").addEventListener("click", () => { if ((state.page + 1) * PAGE_SIZE < state.matches.length) { state.page += 1; renderFindings(); } });
  window.addEventListener("pagehide", stopPolling);
  void refreshHealth();
  let previous = new URL(window.location.href).searchParams.get("analysis");
  if (!previous) { try { previous = localStorage.getItem("local-ai-analysis-id"); } catch { /* Optional persistence. */ } }
  if (previous && UUID.test(previous)) void poll(activate(previous));
  updateButtons();
})();
