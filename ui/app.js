(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const content = $("view-content");
  const titles = { history: "History", turn: "Turn & causal tree", proposals: "Proposals", deadletters: "Dead letters", deployments: "Deployments", cluster: "Cluster" };
  let token = "";
  let session = null;
  let controller = null;
  let authVersion = 0;
  let oidcEnabled = false;
  const oidcReasons = {
    not_configured: "OIDC has no admitted enabled profile.",
    profile_mismatch: "The startup OIDC profile differs from the admitted profile.",
    provider_unavailable: "The OIDC provider is unavailable.",
    configuration_pending: "An OIDC configuration change is pending.",
    restart_required: "The admitted OIDC listener settings require a restart."
  };

  function element(tag, text, attrs = {}) {
    const node = document.createElement(tag);
    if (text !== null && text !== undefined) node.textContent = String(text);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    return node;
  }

  function text(value) {
    if (value === null || value === undefined) return "—";
    return typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
  }

  function valueNode(value) {
    return element(typeof value === "object" && value !== null ? "pre" : "span", text(value));
  }

  function fields(values) {
    const list = element("dl");
    for (const [key, value] of Object.entries(values)) {
      list.append(element("dt", key.replaceAll("_", " ")));
      const description = element("dd");
      description.append(valueNode(value));
      list.append(description);
    }
    return list;
  }

  function section(parent, title, id) {
    const node = element("section", null, id ? { id } : {});
    node.append(element("h2", title));
    parent.append(node);
    return node;
  }

  function table(parent, caption, columns, rows) {
    if (!rows.length) {
      parent.append(element("p", `${caption}: no entries.`));
      return;
    }
    const wrapper = element("div", null, { class: "table-scroll", tabindex: "0", role: "region", "aria-label": caption });
    const grid = element("table");
    grid.append(element("caption", caption));
    const head = element("tr");
    for (const [label] of columns) head.append(element("th", label, { scope: "col" }));
    const thead = element("thead");
    thead.append(head);
    grid.append(thead);
    const body = element("tbody");
    for (const row of rows) {
      const tr = element("tr");
      for (const [, read] of columns) {
        const td = element("td");
        const value = read(row);
        td.append(value instanceof Node ? value : valueNode(value));
        tr.append(td);
      }
      body.append(tr);
    }
    grid.append(body);
    wrapper.append(grid);
    parent.append(wrapper);
  }

  function button(label, action, attrs = {}) {
    const control = element("button", label, { type: "button", ...attrs });
    control.addEventListener("click", () => perform(action));
    return control;
  }

  function raw(parent, label, value) {
    const detail = element("details");
    detail.append(element("summary", label), element("pre", JSON.stringify(value, null, 2)));
    parent.append(detail);
  }

  function turnLink(id) {
    return id ? element("a", id, { href: `#turn/${encodeURIComponent(id)}`, "data-testid": "turn-open" }) : element("span", "—");
  }

  function turnPair(item) {
    const node = element("div");
    node.append(element("span", "Production: "), turnLink(item.turn_prod), element("br"), element("span", "Fork: "), turnLink(item.turn_fork));
    return node;
  }

  function has(scope) {
    return Boolean(session?.authenticated && (session.scopes.includes(scope) || session.scopes.includes("admin")));
  }

  function notice(parent, message) {
    parent.append(element("p", message, { class: "notice" }));
  }

  function report(error) {
    if (error.name === "AbortError") return;
    $("error").textContent = error.message || "The operation failed.";
    $("error").hidden = false;
    $("status").textContent = "Operation failed. See the error above.";
  }

  async function perform(action) {
    try { await action(); } catch (error) { report(error); }
  }

  function clearAuth() {
    authVersion += 1;
    token = "";
    session = null;
    $("bearer-token").value = "";
    $("logout-reason").value = "";
    $("error").textContent = "";
    $("error").hidden = true;
    $("status").textContent = "";
    controller?.abort();
    content.replaceChildren();
    content.setAttribute("aria-busy", "false");
    updateAuth();
  }

  async function request(path, { method = "GET", body, signal = controller?.signal } = {}) {
    const headers = { Accept: "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      if (!token) {
        if (!session?.csrf_token) throw new Error("A current cookie session with a CSRF token is required. Sign in again.");
        headers["X-Kronik-CSRF"] = session.csrf_token;
      }
    }
    let response;
    try {
      response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: token ? "omit" : "same-origin", cache: "no-store", redirect: "error", signal });
    } catch (error) {
      if (error.name === "AbortError") throw error;
      throw new Error("The API could not be reached. Check the connection and try again.");
    }
    let data = null;
    if (response.status !== 204) {
      try { data = await response.json(); } catch {
        if (response.status === 401 || response.status === 403) clearAuth();
        throw new Error(`The API returned an invalid JSON response (HTTP ${response.status}).`);
      }
    }
    if (signal?.aborted) throw new DOMException("Request cancelled", "AbortError");
    if (!response.ok) {
      const failure = data?.error;
      const message = [failure?.code || `HTTP ${response.status}`, failure?.message || "The API rejected the request.", failure?.hint].filter(Boolean).join("\n");
      if (response.status === 401 || response.status === 403) clearAuth();
      throw new Error(message);
    }
    return data;
  }

  function updateAuth() {
    const authenticated = Boolean(session?.authenticated);
    $("login-link").hidden = !oidcEnabled;
    $("logout-form").hidden = !authenticated;
    const oidcStatus = oidcEnabled ? "" : ` ${oidcReasons[session?.oidc_reason] || "OIDC is unavailable."}`;
    if (!authenticated) {
      $("session-status").textContent = `Not signed in. ${oidcEnabled ? "Use OIDC or a bearer token" : "Use a bearer token"} to read data.${oidcStatus}`;
    } else {
      $("session-status").textContent = `${token ? "Bearer token" : session.principal ? `OIDC: ${session.principal}` : "Authenticated session"}. Scopes: ${session.scopes.join(", ") || "none"}.${session.expires_at_ms ? ` Expires: ${new Date(session.expires_at_ms).toLocaleString()}.` : ""}${oidcStatus}`;
    }
  }

  async function checkSession() {
    const version = ++authVersion;
    const data = await request("/v1/auth/session", { signal: null });
    if (version !== authVersion) return false;
    session = data;
    oidcEnabled = data.oidc_enabled;
    if (!data.authenticated) token = "";
    updateAuth();
    return true;
  }

  function reasonValue(input) {
    const reason = input.value;
    if (!reason.trim()) throw new Error("A non-blank reason is required.");
    if (new TextEncoder().encode(reason).length > 4096) throw new Error("The reason must be at most 4096 UTF-8 bytes.");
    return reason;
  }

  function mutation(parent, name, label, scope, path, description, onSuccess) {
    const area = section(parent, label, `${name}-section`);
    area.className = "mutation";
    area.append(element("p", description));
    const form = element("form", null, { id: `${name}-form` });
    const reason = element("input", null, { id: `${name}-reason`, required: "", maxlength: "4096", autocomplete: "off" });
    const dry = element("input", null, { id: `${name}-dry-run`, type: "checkbox" });
    const check = element("label", null, { class: "check" });
    check.append(dry, document.createTextNode("Dry run (validate without changing anything)"));
    const submit = element("button", label, { id: `${name}-button`, type: "submit", "aria-describedby": `${name}-scope` });
    const allowed = has(scope);
    let completed = false;
    submit.disabled = !allowed;
    const explanation = element("p", allowed ? `Requires ${scope} scope. Every real change records your reason and caller identity.` : `Disabled: missing ${scope} scope (or admin).`, { id: `${name}-scope` });
    form.append(element("label", "Reason", { for: reason.id }), reason, check, submit);
    area.append(explanation, form);
    const result = element("div", null, { id: `${name}-result` });
    area.append(result);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      perform(async () => {
        if (!has(scope)) throw new Error(`Missing ${scope} scope.`);
        const body = { reason: reasonValue(reason), dry_run: dry.checked };
        submit.disabled = true;
        $("error").hidden = true;
        try {
          const data = await request(path, { method: "POST", body });
          result.replaceChildren();
          result.append(element("h3", body.dry_run ? "Dry run result — nothing changed" : `${label} result`));
          result.append(fields(data || {}));
          if (data?.turn_id) result.append(turnLink(data.turn_id));
          $("status").textContent = body.dry_run ? `${label} dry run completed. Nothing changed.` : `${label} completed.`;
          if (!body.dry_run) {
            completed = name === "resend";
            if (completed) explanation.textContent = "This input has been resent. Select its new turn to inspect the outcome.";
            if (onSuccess) await onSuccess(data);
          }
        } finally { submit.disabled = completed || !has(scope); }
      });
    });
  }

  async function historyView(signal) {
    const form = element("form", null, { id: "actor-filter" });
    const kind = element("input", null, { id: "actor-kind", autocomplete: "off" });
    form.append(element("label", "Actor kind", { for: kind.id }), kind, element("button", "Filter actors", { type: "submit" }));
    content.append(form);
    const actors = section(content, "Actors", "actors");
    const selected = section(content, "Actor history", "actor-history");
    selected.append(element("p", "Select an actor to read its turns."));
    let selection = 0;
    async function loadActor(actor, before) {
      const current = ++selection;
      selected.replaceChildren(element("h2", `Actor history: ${actor.kind}/${actor.key}`));
      selected.append(element("p", "Loading turns…"));
      const query = new URLSearchParams({ limit: "50" });
      if (before !== undefined) query.set("before", before);
      const data = await request(`/v1/actors/${encodeURIComponent(actor.kind)}/${encodeURIComponent(actor.key)}/history?${query}`, { signal });
      if (current !== selection) return;
      selected.replaceChildren(element("h2", `Actor history: ${actor.kind}/${actor.key}`), fields({ schema_version: actor.schema_version, turns: actor.turns, sql: actor.sql }));
      table(selected, "Turns (newest first)", [
        ["Turn", (turn) => turnLink(turn.turn_id)], ["LSN / logical time (ms)", (turn) => `${turn.lsn} / ${turn.logical_time_ms}`],
        ["Input", (turn) => `${turn.input.type}: ${turn.input.summary}`], ["Outcome", (turn) => turn.outcome],
        ["Writes / SQL changes / fuel", (turn) => `${turn.writes.length} / ${turn.sql_changes} / ${turn.fuel_used}`], ["Effects", (turn) => turn.effects],
      ], data.turns);
      if (before !== undefined) selected.append(button("Newest turns", () => loadActor(actor), { id: "history-newest" }));
      if (data.next !== null && data.next !== undefined) selected.append(button("Older turns", () => loadActor(actor, data.next), { id: "history-next" }));
      selected.setAttribute("tabindex", "-1");
      selected.focus();
      $("status").textContent = `Loaded ${data.turns.length} turns.`;
    }
    async function loadActors(after) {
      const query = new URLSearchParams({ limit: "50" });
      if (kind.value) query.set("kind", kind.value);
      if (after) query.set("after", after);
      const data = await request(`/v1/actors?${query}`, { signal });
      actors.replaceChildren(element("h2", "Actors"));
      table(actors, "Actors in kind/key order", [
        ["Actor", (actor) => button(`${actor.kind}/${actor.key}`, () => loadActor(actor), { "data-testid": "actor-open" })],
        ["Schema", (actor) => actor.schema_version], ["Turns", (actor) => actor.turns], ["Last turn", (actor) => turnLink(actor.last_turn_id)],
      ], data.actors);
      if (after) actors.append(button("First actors", () => loadActors(), { id: "actors-first" }));
      if (data.next) actors.append(button("Next actors", () => loadActors(data.next), { id: "actors-next" }));
    }
    form.addEventListener("submit", (event) => { event.preventDefault(); perform(() => loadActors()); });
    await loadActors();
  }

  function traceTree(nodes) {
    const list = element("ul");
    for (const node of nodes) {
      const item = element("li");
      item.append(turnLink(node.turn_id), document.createTextNode(` · ${node.actor} · ${node.input.type}: ${node.input.summary} · ${text(node.outcome.kind)}${node.outcome.error_code ? ` (${node.outcome.error_code})` : ""}${node.outcome.message ? ` — ${node.outcome.message}` : ""}`));
      if (node.children.length) item.append(traceTree(node.children));
      list.append(item);
    }
    return list;
  }

  async function turnView(id, signal) {
    const form = element("form", null, { id: "turn-form" });
    const input = element("input", null, { id: "turn-id", required: "", autocomplete: "off" });
    input.value = id || "";
    form.append(element("label", "Turn ID", { for: input.id }), input, element("button", "Open turn", { type: "submit" }));
    form.addEventListener("submit", (event) => { event.preventDefault(); open("turn", input.value); });
    content.append(form);
    if (!id) { notice(content, "Choose a turn from actor history or enter a turn ID."); return; }
    const turn = await request(`/v1/turns/${encodeURIComponent(id)}`, { signal });
    const detail = section(content, `Turn ${turn.turn_id}`, "turn-detail");
    detail.append(fields({ actor: turn.actor, lsn: turn.lsn, logical_time_ms: turn.logical_time_ms, code_hash: turn.code_hash, engine_version: turn.engine_version, config_epoch: turn.config_epoch, schema_version: turn.schema_version, fuel_used: turn.fuel_used, memory_peak_bytes: turn.memory_peak_bytes, causal_id: turn.causal_id, outcome: turn.outcome }));
    raw(detail, "Input and output", { input: turn.input, output: turn.output });
    table(detail, "Effects", [ ["Ordinal", (effect) => effect.ordinal], ["Kind / target", (effect) => `${effect.kind} / ${effect.target}`], ["Status / delivery", (effect) => `${effect.status} / ${text(effect.delivery)}`], ["Request", (effect) => effect.request], ["Grounding / simulator", (effect) => `${text(effect.grounding)} / ${text(effect.simulator)}`], ["Error / remedy", (effect) => [effect.error, effect.hint].filter(Boolean).join("\n") ] ], turn.effects);
    raw(detail, "State, SQL, messages and timers", { writes: turn.writes, sql_schema: turn.sql_schema, sql_changes: turn.sql_changes, messages: turn.messages, timers: turn.timers, compensations: turn.compensations });
    raw(detail, "Full turn JSON", turn);
    const trace = await request(`/v1/turns/${encodeURIComponent(id)}/trace`, { signal });
    const tree = section(content, "Causal tree", "causal-tree");
    tree.className = "causal-tree";
    tree.append(fields({ actor: trace.actor, root: trace.root }));
    const ancestors = element("ol");
    for (const ancestor of trace.ancestors) {
      const item = element("li");
      item.append(turnLink(ancestor.turn_id), document.createTextNode(` · ${ancestor.input.summary} · ${text(ancestor.outcome.kind)}`));
      ancestors.append(item);
    }
    tree.append(element("h3", "Ancestors (root to parent)"));
    if (trace.ancestors.length) tree.append(ancestors); else tree.append(element("p", "No retained ancestors."));
    tree.append(element("h3", "Selected turn and descendants"), traceTree([{ turn_id: trace.turn.turn_id, actor: trace.actor, input: trace.turn.input, outcome: trace.turn.outcome, children: trace.descendants }]));
    if (trace.truncated) notice(tree, "The server truncated this causal tree at its retained-data or 1,000-turn limit.");
  }

  function comparisons(parent, title, items, name) {
    table(parent, title, [["Change", name], ["Production", (row) => row.prod], ["Fork", (row) => row.fork]], items);
  }

  function stateChanges(parent, title, entries) {
    const area = section(parent, title);
    if (!entries.length) area.append(element("p", "No state differences."));
    for (const entry of entries) {
      const actor = element("article");
      actor.append(element("h3", entry.actor));
      if (entry.root_lsn !== undefined) actor.append(element("p", `Root LSN: ${entry.root_lsn}`));
      comparisons(actor, "Key-value changes", entry.keys, (row) => `${row.op}: ${row.key}`);
      comparisons(actor, "SQL row changes", entry.sql, (row) => `${row.op}: ${row.table} · primary key ${text(row.pk)}`);
      area.append(actor);
    }
  }

  function renderDiff(parent, diff) {
    const summary = section(parent, "Diff summary", "diff-summary");
    summary.append(fields(diff.summary));
    raw(summary, "Replay base, code and options", { base: diff.base, code: diff.code, options: diff.options });
    if (diff.kinds?.length) raw(summary, "Per-kind summaries", diff.kinds);
    const grounding = section(parent, "Grounding per target", "diff-grounding");
    table(grounding, "External target grounding", [
      ["Kind / target", (row) => `${row.kind}: ${row.method} ${row.host}${row.route}`], ["Exact", (row) => row.exact], ["Approximate", (row) => row.approximate], ["Synthetic", (row) => row.synthetic], ["Synthetic by", (row) => row.synthetic_by], ["Live", (row) => row.live], ["Forked", (row) => row.forked], ["Confidence", (row) => row.confidence],
    ], diff.grounding);
    const responses = section(parent, "Responses", "diff-responses");
    responses.append(fields({ changed: diff.responses.changed, unchanged: diff.responses.unchanged }));
    for (const response of diff.responses.items) {
      const article = element("article");
      article.append(element("h3", `${response.route} · root ${response.root_lsn}`), turnPair(response), fields({ production_status: response.status.prod, fork_status: response.status.fork }));
      comparisons(article, "Changed response headers", response.headers, (row) => row.name);
      comparisons(article, "Response body operations", response.body, (row) => `${row.op} ${row.path || "(whole body)"}`);
      responses.append(article);
    }
    const effects = section(parent, "Effects", "diff-effects");
    effects.append(fields({ added: diff.effects.added, removed: diff.effects.removed, changed: diff.effects.changed }));
    for (const effect of diff.effects.items) {
      const article = element("article");
      article.append(element("h3", `${effect.change}: ${effect.kind} ${effect.method} ${effect.host}${effect.route}`), turnPair(effect), fields({ grounding: effect.grounding, simulator: effect.simulator }));
      comparisons(article, "Changed effect fields", effect.fields, (row) => row.field);
      effects.append(article);
    }
    stateChanges(parent, "State — isolated replay", diff.state.isolated);
    stateChanges(parent, "State — continuous replay", diff.state.continuous);
    const cumulative = section(parent, "Cumulative drift", "diff-cumulative");
    cumulative.append(fields({ actors_changed: diff.cumulative.actors_changed }));
    stateChanges(cumulative, "Cumulative actor changes", diff.cumulative.items);
    const causes = section(parent, "Causes", "diff-causes");
    table(causes, "Origins and consequences by input", [["Kind", (row) => row.kind], ["Input", (row) => row.input], ["Origins", (row) => row.origins], ["Consequences", (row) => row.consequences], ["Root inputs", (row) => row.root_inputs], ["Sample turns", (row) => sampleLinks(row.samples)]], diff.causes);
    const errors = section(parent, "Errors", "diff-errors");
    errors.append(fields({ introduced: diff.errors.introduced, fixed: diff.errors.fixed, new_orphans: diff.errors.new_orphans, outcome_unknown: diff.errors.outcome_unknown }));
    table(errors, "Error details", [["Change", (row) => row.kind], ["Error code", (row) => row.error_code], ["Message", (row) => row.message], ["Input", (row) => row.input], ["Turns", turnPair]], diff.errors.items);
    const resources = section(parent, "Resources", "diff-resources");
    table(resources, "Matched-turn resource percentiles", [["Resource", (row) => row.name], ["Production p50 / p95 / p99", (row) => `${row.value.prod.p50} / ${row.value.prod.p95} / ${row.value.prod.p99}`], ["Fork p50 / p95 / p99", (row) => `${row.value.fork.p50} / ${row.value.fork.p95} / ${row.value.fork.p99}`], ["p99 relative change", (row) => row.change]], [ { name: "Fuel", value: diff.resources.fuel, change: diff.resources.fuel_p99_change }, { name: "Memory (bytes)", value: diff.resources.memory, change: diff.resources.memory_p99_change } ]);
    const samples = section(parent, "Sample turns", "diff-samples");
    for (const [category, entries] of Object.entries(diff.samples)) {
      samples.append(element("h3", category.replaceAll("_", " ")), sampleLinks(entries));
    }
    if (diff.irreversible) {
      const irreversible = section(parent, "Irreversible effects", "diff-irreversible");
      notice(irreversible, "These external effects cannot be undone by restoring actor state.");
      irreversible.append(fields({ count: diff.irreversible.count }));
      table(irreversible, "Irreversible effect details", [["Production turn", (row) => turnLink(row.turn_prod)], ["Target", (row) => `${row.kind}: ${row.method} ${row.host}${row.route}`], ["Status", (row) => row.status], ["Delivery", (row) => row.delivery], ["Idempotency key", (row) => row.idempotency_key]], diff.irreversible.items);
    }
    raw(parent, "Full diff JSON (server redactions preserved)", diff);
  }

  function sampleLinks(entries) {
    const list = element("ul");
    for (const entry of entries || []) {
      const item = element("li");
      if (typeof entry === "string") item.append(turnLink(entry));
      else item.append(turnLink(entry.turn), document.createTextNode(` · ${entry.method} ${entry.route} · ${entry.status} · ${entry.outcome}`));
      list.append(item);
    }
    if (!list.children.length) return element("span", "No samples.");
    return list;
  }

  async function proposalView(id, signal) {
    if (!id) {
      const data = await request("/v1/proposals", { signal });
      table(content, "Proposals", [["Proposal", (proposal) => element("a", proposal.id, { href: `#proposals/${encodeURIComponent(proposal.id)}`, "data-testid": "proposal-open" })], ["Status", (proposal) => proposal.status], ["Kinds", (proposal) => proposal.kinds.map((kind) => kind.kind).join(", ")], ["Verified through LSN", (proposal) => proposal.verified_through_lsn], ["Policy", (proposal) => proposal.policy]], data.proposals);
      return;
    }
    const proposal = await request(`/v1/proposals/${encodeURIComponent(id)}`, { signal });
    const detail = section(content, `Proposal ${proposal.id}`, "proposal-detail");
    detail.append(fields({ status: proposal.status, fork: proposal.fork, fork_lsn: proposal.fork_lsn, verified_through_lsn: proposal.verified_through_lsn, diff_hash: proposal.diff_hash, kinds: proposal.kinds, unchanged: proposal.unchanged, policy: proposal.policy }));
    for (const warning of proposal.warnings || []) notice(detail, warning);
    if (proposal.progress) detail.append(fields({ progress: proposal.progress }));
    if (proposal.error) detail.append(fields({ error: proposal.error }));
    if (proposal.rebase) raw(detail, "Rollback via replay", proposal.rebase);
    raw(detail, "Approval requests", proposal.approval_requests);
    table(detail, "Completed approvals", [["Authenticated principal", (approval) => approval.token_id], ["Historical verified OIDC identity (pii:read)", (approval) => approval.verified_identity || "Not disclosed or not recorded"], ["Reason", (approval) => approval.reason], ["Diff hash", (approval) => approval.diff_hash], ["Verified through LSN", (approval) => approval.verified_through_lsn], ["Approval LSN", (approval) => approval.lsn], ["Time", (approval) => new Date(approval.wall_time_ms).toLocaleString()]], proposal.approvals || []);
    if (!has("pii:read")) notice(detail, "No pii:read scope: values are displayed exactly as redacted by the server. Redacted does not mean verified.");
    if (proposal.status !== "running" && proposal.status !== "failed") {
      const diff = await request(`/v1/proposals/${encodeURIComponent(id)}/diff`, { signal });
      renderDiff(content, diff);
    } else notice(content, proposal.status === "running" ? "Replay is running. Refresh to read progress and the completed diff." : "Replay failed. Read the recorded error; no completed diff is available.");
    mutation(content, "approve", "Approve proposal", "approve", `/v1/proposals/${encodeURIComponent(id)}/approve`, "Approval binds the current diff hash and verified-through LSN to your authenticated principal. Verified OIDC issuer and subject are stored encrypted and revealed only with pii:read.");
    mutation(content, "promote", "Promote proposal", "promote", `/v1/proposals/${encodeURIComponent(id)}/promote`, "Promotion catches up to main and atomically switches code. The server enforces policy, approval and freshness; a real promotion changes production.");
    notice(content, "Refresh this proposal after a real mutation to read its current status and any catch-up diff changes.");
  }

  async function deadlettersView(id, signal) {
    const listing = section(content, "Dead letters", "deadletter-list");
    const selected = section(content, "Resend", "deadletter-detail");
    let selectedLetter = null;
    async function load(after) {
      const query = new URLSearchParams({ limit: "50" });
      if (after) query.set("after", after);
      const data = await request(`/v1/dead-letters?${query}`, { signal });
      listing.replaceChildren(element("h2", "Dead letters"));
      table(listing, "Failed inputs and uncertain outcomes", [["ID", (letter) => button(letter.id, () => select(letter), { "data-testid": "deadletter-open" })], ["Actor", (letter) => letter.actor], ["Input", (letter) => `${letter.input.type}: ${letter.input.summary}`], ["Error", (letter) => `${letter.error_code}: ${letter.message}`], ["Resent as", (letter) => turnLink(letter.resent_as)]], data.dead_letters);
      if (after) listing.append(button("First dead letters", () => load(), { id: "deadletters-first" }));
      if (data.dead_letters.length === 50) listing.append(button("Next dead letters", () => load(data.dead_letters[data.dead_letters.length - 1].id), { id: "deadletters-next" }));
      if (id && !selectedLetter) {
        const match = data.dead_letters.find((letter) => letter.id === id);
        if (match) select(match);
      }
    }
    function select(letter) {
      selectedLetter = letter;
      selected.replaceChildren(element("h2", `Dead letter ${letter.id}`), fields(letter));
      if (letter.resent_as) {
        selected.append(element("p", "Already resent as "), turnLink(letter.resent_as));
      } else {
        mutation(selected, "resend", "Resend dead letter", "operate", `/v1/dead-letters/${encodeURIComponent(letter.id)}/resend`, "Resend the original input as a new root input. A real resend may perform production effects.", async (data) => {
          if (data?.turn_id) letter.resent_as = data.turn_id;
          await load();
        });
      }
      selected.setAttribute("tabindex", "-1");
      selected.focus();
    }
    selected.append(element("p", "Select a dead letter to review and resend it."));
    await load();
  }

  async function deploymentsView(signal) {
    const data = await request("/v1/deployments", { signal });
    if (!data.deployments.length) { notice(content, "No deployments recorded."); return; }
    const timeline = element("ol", null, { class: "timeline", id: "deployment-timeline", "aria-label": "Deployment timeline, oldest first" });
    for (const deployment of data.deployments) {
      const item = element("li");
      const article = element("article");
      article.append(element("h2", `Epoch ${deployment.epoch}`), fields({ lsn: deployment.lsn, cause: deployment.cause, reason: deployment.reason, caller: deployment.token_id }));
      table(article, `Code at epoch ${deployment.epoch}`, [["Kind", (kind) => kind.kind], ["Code hash", (kind) => kind.code_hash], ["Schema", (kind) => kind.schema_version]], deployment.kinds);
      item.append(article);
      timeline.append(item);
    }
    content.append(timeline);
  }

  async function clusterView(signal) {
    const data = await request("/v1/cluster/status", { signal });
    const area = section(content, "Cluster status", "cluster-status");
    for (const [key, value] of Object.entries(data)) {
      if (Array.isArray(value) && value.length && value.every((row) => row !== null && typeof row === "object" && !Array.isArray(row))) {
        const keys = [...new Set(value.flatMap((row) => Object.keys(row)))];
        table(area, key.replaceAll("_", " "), keys.map((name) => [name.replaceAll("_", " "), (row) => row[name]]), value);
      } else area.append(fields({ [key]: value }));
    }
  }

  function open(view, id) {
    const hash = `#${view}${id ? `/${encodeURIComponent(id)}` : ""}`;
    if (location.hash === hash) perform(() => navigate());
    else location.hash = hash;
  }

  async function navigate(focus = true) {
    controller?.abort();
    controller = new AbortController();
    const signal = controller.signal;
    const [requested, encoded] = location.hash.slice(1).split("/");
    const view = Object.hasOwn(titles, requested) ? requested : "history";
    content.replaceChildren();
    $("error").hidden = true;
    $("error").textContent = "";
    $("status").textContent = "Loading…";
    $("view-title").textContent = titles[view];
    document.title = `Kronik · ${titles[view]}`;
    for (const key of Object.keys(titles)) {
      const link = $(`nav-${key}`);
      if (key === view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    if (focus) $("view-title").focus();
    content.setAttribute("aria-busy", "true");
    try {
      if (!has("read")) {
        notice(content, session?.authenticated ? "Missing read scope (or admin). Ask an operator for access." : "Sign in to load real data from the public API.");
        $("status").textContent = "Authentication and read scope are required.";
        return;
      }
      content.append(button("Refresh view", () => navigate(), { id: "refresh-button" }));
      const id = encoded ? decodeURIComponent(encoded) : null;
      if (view === "history") await historyView(signal);
      else if (view === "turn") await turnView(id, signal);
      else if (view === "proposals") await proposalView(id, signal);
      else if (view === "deadletters") await deadlettersView(id, signal);
      else if (view === "deployments") await deploymentsView(signal);
      else if (view === "cluster") await clusterView(signal);
      if (!signal.aborted) $("status").textContent = `${titles[view]} loaded.`;
    } finally {
      if (!signal.aborted) content.setAttribute("aria-busy", "false");
    }
  }

  $("token-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const supplied = $("bearer-token").value;
    clearAuth();
    token = supplied;
    $("token-connect").disabled = true;
    perform(async () => {
      try {
        if (await checkSession()) {
          if (!session.authenticated) throw new Error("The bearer token was not authenticated.");
          $("token-alternative").open = false;
          await navigate();
        }
      } catch (error) { clearAuth(); throw error; }
      finally { $("token-connect").disabled = false; }
    });
  });

  $("logout-form").addEventListener("submit", (event) => {
    event.preventDefault();
    perform(async () => {
      const body = { reason: reasonValue($("logout-reason")), dry_run: $("logout-dry-run").checked };
      $("logout-button").disabled = true;
      try {
        if (!token) await request("/v1/auth/logout", { method: "POST", body, signal: null });
        if (body.dry_run) $("status").textContent = "Logout dry run completed. You remain signed in.";
        else {
          clearAuth();
          $("logout-reason").value = "";
          await checkSession();
          await navigate();
          $("status").textContent = session?.authenticated ? "Bearer token discarded. An existing cookie session is still signed in." : "Signed out of this tab. Ordinary bearer tokens are not revoked.";
        }
      } finally { $("logout-button").disabled = false; }
    });
  });

  document.querySelector('a[href="#main"]').addEventListener("click", (event) => {
    event.preventDefault();
    $("main").focus();
  });
  window.addEventListener("hashchange", () => perform(() => navigate()));
  perform(async () => {
    try {
      await checkSession();
      await navigate(false);
    } catch (error) { clearAuth(); throw error; }
  });
})();
