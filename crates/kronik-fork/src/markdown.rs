//! Markdown rendering of a diff (docs/design/m3-fork.md §5.11).
//! Deterministic like the JSON.

use std::fmt::Write as _;

use serde_json::Value;

use crate::diff::{ActorState, Diff, FieldDiff, KeyDiff, SqlDiff};

/// What a fork did with a `fork_mode = "sandbox"` foreign actor (M14).
pub fn foreign_line(f: &crate::diff::ForeignFork) -> String {
    match f.checkpoint_lsn {
        Some(lsn) if f.mode == "sandbox" => format!(
            "a copy from the checkpoint at LSN {lsn}, {} recorded call{} replayed",
            f.replayed_calls,
            if f.replayed_calls == 1 { "" } else { "s" }
        ),
        _ => format!("recorded answers ({})", f.why),
    }
}

/// `3 (contract 2, fail-closed 1)`: synthetic answers per simulator (M12).
fn synthetic(n: u64, by: &std::collections::BTreeMap<String, u64>) -> String {
    if by.is_empty() {
        return num(n);
    }
    let parts: Vec<String> = by.iter().map(|(k, v)| format!("{k} {}", num(*v))).collect();
    format!("{} ({})", num(n), parts.join(", "))
}

/// `10412` -> `10 412`.
fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// A percentage with one decimal; one that rounds to zero is `0.0 %`, never
/// `-0.0 %`.
fn pct(x: f64) -> String {
    let s = format!("{:.1}", x * 100.0);
    format!("{} %", if s == "-0.0" { "0.0" } else { s.as_str() })
}

fn val(v: &Value) -> String {
    match v {
        Value::Null => "∅".into(),
        // A subject's value: which subject (a keyed pseudonym `s:…`, never
        // the id) and whether it changed (a keyed hash), not what.
        Value::Object(o) if o.get("redacted") == Some(&Value::Bool(true)) => format!(
            "`[sealed:{} {}]`",
            o.get("subject").and_then(Value::as_str).unwrap_or("?"),
            o.get("hash").and_then(Value::as_str).unwrap_or("")
        ),
        Value::String(s) => format!("`{}`", s.replace('`', "'").replace('\n', "\\n")),
        other => format!("`{other}`"),
    }
}

fn field_lines(out: &mut String, fields: &[FieldDiff]) {
    for f in fields {
        let _ = writeln!(out, "  - {}: {} → {}", f.field, val(&f.prod), val(&f.fork));
    }
}

fn key_lines(out: &mut String, keys: &[KeyDiff], sql: &[SqlDiff]) {
    for k in keys {
        let _ = writeln!(
            out,
            "  - key `{}` ({}): {} → {}",
            k.key,
            k.op,
            val(&k.prod),
            val(&k.fork)
        );
    }
    for s in sql {
        let pk = Value::Array(s.pk.clone());
        let _ = writeln!(
            out,
            "  - table `{}` {} {pk}: {} → {}",
            s.table,
            s.op,
            val(&s.prod),
            val(&s.fork)
        );
    }
}

fn actor_states(out: &mut String, items: &[ActorState]) {
    for a in items {
        let _ = writeln!(out, "- `{}`", a.actor);
        key_lines(out, &a.keys, &a.sql);
    }
}

/// Renders the diff; `policy` is the evaluation JSON (§7) when known.
pub fn render(d: &Diff, policy: Option<&Value>) -> String {
    let mut o = String::new();
    overview(&mut o, d, policy, "Behavior diff", false);
    render_details(&mut o, d);
    o
}

/// A string interpolated into the public summary, as inline code: it cannot
/// end the code span (backticks), break a line, or end a table cell (`|`
/// escaped; backslashes dropped so `\|` stays an escape), so it adds no
/// link, image, mention or HTML (M10, ADR 0023).
fn code(s: &str) -> String {
    let s: String = s
        .chars()
        .filter(|c| *c != '`' && *c != '\\' && !c.is_control())
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return "(none)".into();
    }
    format!("`{}`", s.replace('|', "\\|"))
}

/// The host a summary's grounding row shows: for `http.fetch` the most
/// specific `http:` grant pattern that matches it, so a wildcard grant's
/// subdomain (runtime data) shows as `*.suffix`, and `(no grant)` without
/// one; other kinds name a declared foreign actor or secret.
fn grant_host<'a>(kind: &str, host: &'a str, http_grants: &[&'a str]) -> &'a str {
    if kind != "http.fetch" {
        return host;
    }
    http_grants
        .iter()
        .filter_map(|p| Some((kronik_effects::config::http_match(p, host)?, *p)))
        .max_by_key(|(score, _)| *score)
        .map_or("(no grant)", |(_, p)| p)
}

/// A grounding row's method as the summary shows it: one a route may
/// declare, else `(other)`. The guest chooses the string freely and a fork
/// sends nothing, so nothing else validates it (ADR 0023). Other effect
/// kinds have none.
fn public_method(m: &str) -> &str {
    if m.is_empty() || kronik_sched::METHODS.contains(&m) {
        m
    } else {
        "(other)"
    }
}

/// An actor kind as the summary shows it: one with code before or after,
/// else `(undeployed kind)`. A send to a kind that does not exist names a
/// kind the proposed code chose (ADR 0023).
fn public_kind<'a>(d: &Diff, kind: &'a str) -> &'a str {
    if d.code
        .before
        .iter()
        .chain(&d.code.after)
        .any(|c| c.kind == kind)
    {
        kind
    } else {
        "(undeployed kind)"
    }
}

/// The short summary for public places such as a pull request (M10,
/// `kronik diff show --summary`): the overview and counts, causes by actor
/// kind and declared input pattern, grounding per effect kind, method and
/// granted host, and error codes. It never shows a URL path or route, a
/// response body or header, a state key or value, an SQL row, an effect's
/// fields, an error message, an actor's key, a method no route may declare
/// or a kind with no code; every interpolated string is inline code.
/// `http_grants` are the `http:` grant patterns in force.
pub fn summary(d: &Diff, policy: Option<&Value>, http_grants: &[&str]) -> String {
    let mut o = String::new();
    overview(&mut o, d, policy, "Behavior diff summary", true);
    let r = &d.responses;
    let e = &d.effects;
    let er = &d.errors;
    // The kinds' totals; the state lists are capped (`MAX_ITEMS`).
    let actors_changed = if d.kinds.is_empty() {
        d.state
            .isolated
            .iter()
            .map(|s| s.actor.as_str())
            .chain(d.state.continuous.iter().map(|s| s.actor.as_str()))
            .collect::<std::collections::BTreeSet<&str>>()
            .len() as u64
    } else {
        d.kinds.iter().map(|k| k.actors_changed).sum()
    };
    let _ = writeln!(o, "\n## Changes\n");
    let _ = writeln!(o, "| | |\n| --- | --- |");
    let _ = writeln!(
        o,
        "| Responses | {} changed, {} unchanged |",
        num(r.changed),
        num(r.unchanged)
    );
    let _ = writeln!(
        o,
        "| Effects | {} added, {} removed, {} changed |",
        num(e.added),
        num(e.removed),
        num(e.changed)
    );
    let _ = writeln!(
        o,
        "| State | {} actors changed, {} drifting (cumulative) |",
        num(actors_changed),
        num(d.cumulative.actors_changed)
    );
    let _ = writeln!(
        o,
        "| Errors | {} introduced, {} fixed, {} new orphans, {} outcome unknown |",
        num(er.introduced),
        num(er.fixed),
        num(er.new_orphans),
        num(er.outcome_unknown)
    );
    let _ = writeln!(
        o,
        "| Resources | fuel p99 {:+.1} %, memory p99 {:+.1} % |",
        d.resources.fuel_p99_change * 100.0,
        d.resources.memory_p99_change * 100.0
    );
    let mut codes: std::collections::BTreeMap<(&str, &str), u64> = Default::default();
    let mut listed: std::collections::BTreeMap<&str, u64> = Default::default();
    for i in &er.items {
        *codes
            .entry((i.kind.as_ref(), i.error_code.as_str()))
            .or_default() += 1;
        *listed.entry(i.kind.as_ref()).or_default() += 1;
    }
    if !codes.is_empty() {
        let _ = writeln!(o, "\n## Error codes\n");
        for ((kind, error_code), n) in codes {
            let total = match kind {
                "introduced" => er.introduced,
                "fixed" => er.fixed,
                "new_orphan" => er.new_orphans,
                _ => er.outcome_unknown,
            };
            // The items are capped per kind (`MAX_ERRORS`): a lower bound then.
            let n = if listed.get(kind).copied().unwrap_or(0) < total {
                format!("at least {}", num(n))
            } else {
                num(n)
            };
            let _ = writeln!(o, "- {}: {} × {n}", code(kind), code(error_code));
        }
    }
    if !d.causes.is_empty() {
        let _ = writeln!(o, "\n## Causes\n");
        for c in d.causes.iter().take(10) {
            let _ = writeln!(
                o,
                "- {} {}: {} origins, {} consequences in {} root inputs",
                code(public_kind(d, &c.kind)),
                code(&c.input),
                num(c.origins),
                num(c.consequences),
                num(c.root_inputs)
            );
        }
    }
    // Per (kind, method, granted host): never the route, whose segments can
    // be user data (an e-mail address, a phone number).
    let mut targets: std::collections::BTreeMap<(&str, &str, &str), [u64; 5]> = Default::default();
    for g in &d.grounding {
        let t = targets
            .entry((
                g.kind.as_str(),
                public_method(&g.method),
                grant_host(&g.kind, &g.host, http_grants),
            ))
            .or_default();
        for (sum, n) in t
            .iter_mut()
            .zip([g.exact, g.approximate, g.synthetic, g.live, g.forked])
        {
            *sum += n;
        }
    }
    let mut rows: Vec<_> = targets.into_iter().collect();
    rows.sort_by_key(|(_, [_, a, s, _, f])| a + s + f == 0);
    if !rows.is_empty() {
        // Forked answers (M14) get a column only when there are some.
        let forked = rows.iter().any(|(_, [.., f])| *f > 0);
        let _ = writeln!(o, "\n## Grounding\n");
        let _ = writeln!(
            o,
            "| Kind | Method | Host | Exact | Approximate | Synthetic | Live |{} Confidence |",
            if forked { " Forked |" } else { "" }
        );
        let _ = writeln!(
            o,
            "| --- | --- | --- | --- | --- | --- | --- |{} --- |",
            if forked { " --- |" } else { "" }
        );
        for ((kind, method, host), [e, a, s, l, f]) in rows.iter().take(10) {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | {} | {} |{} {} |",
                code(kind),
                code(method),
                code(host),
                num(*e),
                num(*a),
                num(*s),
                num(*l),
                if forked {
                    format!(" {} |", num(*f))
                } else {
                    String::new()
                },
                pct(*e as f64 / (e + a + s + l + f).max(1) as f64)
            );
        }
        if rows.len() > 10 {
            let _ = writeln!(o, "\n… {} more targets", num(rows.len() as u64 - 10));
        }
    }
    let _ = writeln!(
        o,
        "\nURL paths, bodies, state values and actor keys are left out; the whole diff: {}.",
        code(&format!("kronik diff show {} --md", d.fork))
    );
    o
}

/// The header, the summary table and the actor kinds: counts and code
/// hashes only. `public` (the summary) renders each interpolated string as
/// [`code`] and folds kinds with no code.
fn overview(o: &mut String, d: &Diff, policy: Option<&Value>, title: &str, public: bool) {
    let q: fn(&str) -> String = if public { code } else { str::to_owned };
    let s = &d.summary;
    let _ = writeln!(o, "# {title}: {}\n", q(&d.fork));
    let _ = writeln!(
        o,
        "- Base: {} at LSN {}, window {}..={}",
        q(&d.base.branch),
        d.base.fork_lsn,
        d.base.from_lsn,
        d.base.to_lsn
    );
    if let Some(c) = &d.base.window_cut {
        let _ = writeln!(
            o,
            "- **Window cut by retention**: the {} ms window reaches before LSN {}, the oldest point still kept; only the root inputs after it were replayed",
            c.window_ms, c.kept_from_lsn
        );
    }
    for a in &d.code.after {
        let before = d.code.before.iter().find(|b| b.kind == a.kind);
        if before == Some(a) {
            continue;
        }
        let _ = writeln!(
            o,
            "- Code: {} {} → {} (schema {} → {})",
            q(&a.kind),
            before.map_or_else(|| "(new)".into(), |b| q(&b.code_hash)),
            q(&a.code_hash),
            before.map_or(0, |b| b.schema_version),
            a.schema_version
        );
    }
    if let Some(p) = policy {
        let outcome = q(p.get("outcome").and_then(Value::as_str).unwrap_or("?"));
        let fired: Vec<String> = p
            .get("fired")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|f| {
                let mut line = format!(
                    "{} ({})",
                    q(f.get("name")?.as_str()?),
                    q(f.get("action")?.as_str()?)
                );
                // Only the floor in code has a reason, a text of ours.
                if let Some(reason) = f.get("reason").and_then(Value::as_str) {
                    let _ = write!(line, ": {reason}");
                }
                Some(line)
            })
            .collect();
        let _ = if fired.is_empty() {
            writeln!(o, "- Policy: **{outcome}**")
        } else {
            writeln!(o, "- Policy: **{outcome}**: {}", fired.join(", "))
        };
    }
    let _ = writeln!(o, "\n## Summary\n");
    let _ = writeln!(o, "| | |\n| --- | --- |");
    let _ = writeln!(
        o,
        "| Root inputs | {} (replayed {}, sample {}) |",
        num(s.root_inputs),
        num(s.replayed),
        pct(s.sample)
    );
    let _ = writeln!(
        o,
        "| Turns | production {}, fork {} |",
        num(s.turns_prod),
        num(s.turns_fork)
    );
    let _ = writeln!(
        o,
        "| Divergent turns | {} ({} origins, {} consequences) |",
        num(s.divergent_turns),
        num(s.origins),
        num(s.consequences)
    );
    if s.pii_masked + s.pii_unverified > 0 {
        let _ = writeln!(
            o,
            "| PII-masked turns | {} ({} identical to production; ran on pseudonyms, not verified: re-run with a pii:read token) |",
            num(s.pii_masked + s.pii_unverified),
            num(s.pii_unverified)
        );
    }
    if s.preview_inputs > 0 {
        let _ = writeln!(
            o,
            "| Preview inputs | {} (requests to the preview; not compared with production) |",
            num(s.preview_inputs)
        );
    }
    let _ = writeln!(
        o,
        "| Effects | exact {}, approximate {}, synthetic {}{} (confidence {}) |",
        num(s.exact),
        num(s.approximate),
        synthetic(s.synthetic, &s.synthetic_by),
        if s.forked > 0 {
            format!(", forked {}", num(s.forked))
        } else {
            String::new()
        },
        pct(s.confidence)
    );
    let _ = writeln!(o, "| Verified through | LSN {} |", s.verified_through_lsn);
    let _ = writeln!(o, "| Changed | {} |", if s.changed { "yes" } else { "no" });

    if !d.kinds.is_empty() {
        let _ = writeln!(o, "\n## Actor kinds\n");
        let _ = writeln!(
            o,
            "| Kind | Code | Root inputs | Divergent turns | Responses changed | Effects changed | Actors changed | Errors introduced |"
        );
        let _ = writeln!(o, "| --- | --- | --- | --- | --- | --- | --- | --- |");
        for k in &d.kinds {
            let e = &k.effects;
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} ({} origins) | {} | {} | {} | {} |",
                q(if public {
                    public_kind(d, &k.kind)
                } else {
                    k.kind.as_str()
                }),
                q(&k.code),
                num(k.root_inputs),
                num(k.divergent_turns),
                num(k.origins),
                num(k.responses.changed),
                num(e.added + e.removed + e.changed),
                num(k.actors_changed),
                num(k.errors.introduced)
            );
        }
    }
}

/// Everything `render` shows after the overview: causes, grounding,
/// responses, effects, state, errors, resources and samples.
fn render_details(o: &mut String, d: &Diff) {
    if !d.causes.is_empty() {
        let _ = writeln!(o, "\n## Causes\n");
        for c in &d.causes {
            let sample = c
                .samples
                .first()
                .map(|x| format!(" (e.g. `{x}`)"))
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "- {} `{}`: {} origins, {} consequences in {} root inputs{sample}",
                c.kind,
                c.input,
                num(c.origins),
                num(c.consequences),
                num(c.root_inputs)
            );
        }
    }
    if !d.grounding.is_empty() {
        // The Forked column only when a copy of a foreign actor answered (M14).
        let forked = d.grounding.iter().any(|g| g.forked > 0);
        let (head, rule) = if forked {
            (" Forked |", " --- |")
        } else {
            ("", "")
        };
        let _ = writeln!(o, "\n## Grounding\n");
        let _ = writeln!(
            o,
            "| Kind | Method | Host | Route | Exact | Approximate | Synthetic |{head} Confidence |"
        );
        let _ = writeln!(o, "| --- | --- | --- | --- | --- | --- | --- |{rule} --- |");
        let mut rows: Vec<_> = d.grounding.iter().collect();
        rows.sort_by_key(|g| g.approximate + g.synthetic + g.forked == 0);
        for g in rows {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | {} | {} |{} {} |",
                g.kind,
                g.method,
                g.host,
                g.route,
                num(g.exact),
                num(g.approximate),
                synthetic(g.synthetic, &g.synthetic_by),
                if forked {
                    format!(" {} |", num(g.forked))
                } else {
                    String::new()
                },
                pct(g.confidence)
            );
        }
    }
    if !d.options.foreign.is_empty() {
        let _ = writeln!(o, "\n## Foreign actors\n");
        for f in &d.options.foreign {
            let _ = writeln!(o, "- `{}`: {}", f.name, foreign_line(f));
        }
    }
    let r = &d.responses;
    if r.changed + r.unchanged > 0 {
        let _ = writeln!(o, "\n## Responses\n");
        let _ = writeln!(
            o,
            "{} changed, {} unchanged.",
            num(r.changed),
            num(r.unchanged)
        );
        for i in &r.items {
            let _ = writeln!(
                o,
                "\n- `{}` (root LSN {}, {} → {})",
                i.route,
                i.root_lsn,
                i.turn_prod,
                i.turn_fork.as_deref().unwrap_or("∅")
            );
            if i.status.prod != i.status.fork {
                let st = |x: Option<u32>| x.map_or("∅".to_string(), |v| v.to_string());
                let _ = writeln!(
                    o,
                    "  - status: {} → {}",
                    st(i.status.prod),
                    st(i.status.fork)
                );
            }
            for h in &i.headers {
                let _ = writeln!(
                    o,
                    "  - header {}: {} → {}",
                    h.name,
                    val(&h.prod),
                    val(&h.fork)
                );
            }
            for b in &i.body {
                let path = if b.path.is_empty() {
                    "(body)"
                } else {
                    b.path.as_str()
                };
                let _ = writeln!(
                    o,
                    "  - {} `{path}`: {} → {}",
                    b.op,
                    val(&b.prod),
                    val(&b.fork)
                );
            }
        }
    }
    let e = &d.effects;
    if e.added + e.removed + e.changed > 0 {
        let _ = writeln!(o, "\n## Effects\n");
        let _ = writeln!(
            o,
            "{} added, {} removed, {} changed.\n",
            num(e.added),
            num(e.removed),
            num(e.changed)
        );
        for i in &e.items {
            let _ = writeln!(
                o,
                "- {} {} {} {}{} ({}{}; {} → {})",
                i.change,
                i.kind,
                i.method,
                i.host,
                i.route,
                i.grounding,
                i.simulator
                    .as_deref()
                    .map(|s| format!(": {s}"))
                    .unwrap_or_default(),
                i.turn_prod.as_deref().unwrap_or("∅"),
                i.turn_fork.as_deref().unwrap_or("∅")
            );
            field_lines(o, &i.fields);
        }
    }
    if !d.state.isolated.is_empty() || !d.state.continuous.is_empty() {
        let _ = writeln!(o, "\n## State\n");
        for st in &d.state.isolated {
            let _ = writeln!(o, "- `{}` after root LSN {}", st.actor, st.root_lsn);
            key_lines(o, &st.keys, &st.sql);
        }
        if !d.state.continuous.is_empty() {
            let _ = writeln!(o, "\nFinal state (continuous replay):\n");
            actor_states(o, &d.state.continuous);
        }
    }
    if d.cumulative.actors_changed > 0 {
        let _ = writeln!(o, "\n## Cumulative\n");
        let _ = writeln!(
            o,
            "{} actors drift over the window.\n",
            num(d.cumulative.actors_changed)
        );
        actor_states(o, &d.cumulative.items);
    }
    let er = &d.errors;
    if er.introduced + er.fixed + er.new_orphans + er.outcome_unknown > 0 {
        let _ = writeln!(o, "\n## Errors\n");
        let _ = writeln!(
            o,
            "{} introduced, {} fixed, {} new orphans, {} outcome unknown.\n",
            num(er.introduced),
            num(er.fixed),
            num(er.new_orphans),
            num(er.outcome_unknown)
        );
        for i in &er.items {
            let _ = writeln!(
                o,
                "- {} {} `{}` on `{}` ({} → {})",
                i.kind,
                i.error_code,
                i.message.replace('`', "'"),
                i.input,
                i.turn_prod.as_deref().unwrap_or("∅"),
                i.turn_fork.as_deref().unwrap_or("∅")
            );
        }
    }
    let res = &d.resources;
    let _ = writeln!(o, "\n## Resources\n");
    let _ = writeln!(o, "| | p50 | p95 | p99 |\n| --- | --- | --- | --- |");
    for (name, p) in [
        ("Fuel, production", res.fuel.prod),
        ("Fuel, fork", res.fuel.fork),
        ("Memory, production", res.memory.prod),
        ("Memory, fork", res.memory.fork),
    ] {
        let _ = writeln!(
            o,
            "| {name} | {} | {} | {} |",
            num(p.p50),
            num(p.p95),
            num(p.p99)
        );
    }
    let _ = writeln!(
        o,
        "\nFuel p99 change {}, memory p99 change {}.",
        pct(res.fuel_p99_change),
        pct(res.memory_p99_change)
    );
    if !d.samples.preview.is_empty() {
        let _ = writeln!(o, "\n## Preview inputs\n");
        for p in &d.samples.preview {
            let status = p.status.map_or_else(|| "-".to_owned(), |s| s.to_string());
            let _ = writeln!(
                o,
                "- `{} {}` → {status} {} (`kronik trace {}`)",
                p.method, p.route, p.outcome, p.turn
            );
        }
    }
    let sm = &d.samples;
    let cats = [
        ("Origins", &sm.origins),
        ("Consequences", &sm.consequences),
        ("Changed responses", &sm.responses_changed),
        ("Changed effects", &sm.effects_changed),
        ("Introduced errors", &sm.errors_introduced),
        ("Synthetic effects", &sm.synthetic),
    ];
    if let Some(irr) = &d.irreversible {
        let _ = writeln!(o, "\n## Irreversible effects\n");
        let _ = writeln!(
            o,
            "{} external effects happened under the rolled-back code that the old code \
             would not have made the same way; the rebased state does not account for them.\n",
            num(irr.count)
        );
        if !irr.items.is_empty() {
            let _ = writeln!(o, "| Turn | Effect | Status | Delivery |");
            let _ = writeln!(o, "| --- | --- | --- | --- |");
            for e in &irr.items {
                let _ = writeln!(
                    o,
                    "| `{}` | {} {} {}{} | {} | {} |",
                    e.turn_prod, e.kind, e.method, e.host, e.route, e.status, e.delivery
                );
            }
        }
    }
    if cats.iter().any(|(_, v)| !v.is_empty()) {
        let _ = writeln!(o, "\n## Samples\n");
        for (name, ids) in cats {
            if let Some(first) = ids.first() {
                let _ = writeln!(o, "- {name}: {} (`kronik trace {first}`)", ids.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{code, num, pct, render, summary};
    use crate::diff::{Cause, Diff, ErrorItem, GroundingRow, KindReport};
    use serde_json::{Value, json};

    #[test]
    fn thousands() {
        assert_eq!(num(0), "0");
        assert_eq!(num(999), "999");
        assert_eq!(num(10412), "10 412");
        assert_eq!(num(1234567), "1 234 567");
    }

    /// A diff with a distinct marker in every place that can hold user
    /// data: bodies, headers, state keys and values, SQL rows, effect
    /// fields, error messages, actor keys.
    fn leaky_diff() -> Diff {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/design/fixtures/diff-counter-plus-2.json"
        );
        let mut d: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let v = |s: &str| json!({"text": s});
        d["responses"]["items"] = json!([{
            "root_lsn": 1201, "route": "POST /counter/{key}/{op}",
            "turn_prod": "main:1201", "turn_fork": "p-000000000002:r1201.0",
            "status": {"prod": 200, "fork": 200},
            "headers": [{"name": "x-leak-header", "prod": ["leak-header-prod"], "fork": ["leak-header-fork"]}],
            "body": [{"op": "replace", "path": "/leak-path", "prod": v("leak-body-prod"), "fork": v("leak-body-fork")}]
        }]);
        d["effects"] = json!({"added": 0, "removed": 0, "changed": 1, "items": [{
            "change": "changed", "kind": "http.fetch", "method": "POST", "host": "api.example.com",
            "route": "/v1/{}", "grounding": "approximate", "turn_prod": "main:1201",
            "turn_fork": "p-000000000002:r1201.0",
            "fields": [{"field": "body", "prod": v("leak-effect-prod"), "fork": v("leak-effect-fork")}]
        }]});
        let keys = json!([{"key": "leak-state-key", "op": "set", "prod": v("leak-state-prod"), "fork": {"redacted": true, "subject": "user:leak", "hash": "b3:0000000000000000"}}]);
        let sql = json!([{"table": "leak_table", "op": "update", "pk": ["leak-pk"], "prod": {"body": "leak-row-prod"}, "fork": {"body": "[redacted:user:leak:0000000000000000]"}}]);
        d["state"] = json!({
            "isolated": [{"root_lsn": 1201, "actor": "counter/leak-actor-key", "keys": keys, "sql": sql}],
            "continuous": [{"actor": "counter/leak-actor-key2", "keys": keys, "sql": sql}]
        });
        d["cumulative"] = json!({"actors_changed": 1, "items": [{"actor": "counter/leak-actor-key3", "keys": keys, "sql": sql}]});
        d["errors"]["introduced"] = json!(1);
        d["errors"]["items"] = json!([{
            "kind": "introduced", "error_code": "TURN_FAILED", "message": "leak-error-message",
            "turn_prod": "main:1201", "turn_fork": "p-000000000002:r1201.0", "input": "POST /counter/{key}/{op}"
        }]);
        d.as_object_mut().unwrap().remove("expected_policy");
        serde_json::from_value(d).unwrap()
    }

    #[test]
    fn the_summary_shows_no_bodies_state_values_or_keys() {
        let d = leaky_diff();
        // The full Markdown shows the values (the markers are real).
        let full = render(&d, None);
        for marker in [
            "leak-body-fork",
            "leak-effect-fork",
            "leak-state-prod",
            "leak-row-prod",
        ] {
            assert!(full.contains(marker), "{marker} not in the full diff");
        }
        let s = summary(
            &d,
            Some(
                &json!({"outcome": "deny", "fired": [{"name": "no-new-errors", "action": "deny"}]}),
            ),
            &[],
        );
        assert!(!s.contains("leak"), "the summary leaks:\n{s}");
        assert!(!s.contains("redacted") && !s.contains("user:"), "{s}");
        for want in [
            "# Behavior diff summary: ",
            "**`deny`**: `no-new-errors` (`deny`)",
            "| Responses | 100 changed, 0 unchanged |",
            "| Effects | 0 added, 0 removed, 1 changed |",
            "| State | 2 actors changed, 1 drifting (cumulative) |",
            "- `introduced`: `TURN_FAILED` × 1",
        ] {
            assert!(s.contains(want), "{want}:\n{s}");
        }
    }

    fn row(kind: &str, method: &str, host: &str, route: &str) -> GroundingRow {
        GroundingRow {
            kind: kind.into(),
            method: method.into(),
            host: host.into(),
            route: route.into(),
            exact: 1,
            approximate: 2,
            synthetic: 3,
            synthetic_by: Default::default(),
            live: 4,
            forked: 0,
            confidence: 0.1,
        }
    }

    /// Replaces every string in `v` with a distinct marker `LEAK<n>.` and
    /// records the marker's JSON path.
    fn mark(v: &mut Value, path: &str, paths: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                *s = format!("LEAK{}.", paths.len());
                paths.push(path.to_owned());
            }
            Value::Array(a) => a
                .iter_mut()
                .for_each(|x| mark(x, &format!("{path}[]"), paths)),
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    mark(x, &format!("{path}.{k}"), paths);
                }
            }
            _ => {}
        }
    }

    /// H1, M1: with a marker in every string field of a diff with kinds,
    /// causes, errors and grounding rows, the summary shows only the
    /// allowed fields, and never a URL path, a route or a runtime subdomain.
    #[test]
    fn the_summary_shows_only_allowed_fields() {
        const EMAIL: &str = "/v1/customers/alice.smith@example.com/notify";
        let mut d = serde_json::to_value(leaky_diff()).unwrap();
        d["kinds"] = json!([serde_json::to_value(KindReport {
            kind: "counter".into(),
            code: "changed".into(),
            actors_changed: 2,
            ..Default::default()
        })
        .unwrap()]);
        d["options"]["ignore_headers"] = json!(["h"]);
        d["options"]["live_allowlist"] = json!(["l"]);
        d["grounding"] = serde_json::to_value([
            row("http.fetch", "POST", "x", EMAIL),
            row("http.fetch", "GET", "x", EMAIL),
        ])
        .unwrap();
        let mut paths = Vec::new();
        mark(&mut d, "", &mut paths);
        d["options"]["mode"] = json!("both");
        // The kinds and hosts the grant collapse needs; the routes carry
        // user data.
        for (g, host) in [
            (0usize, "alice-smith.api.example.com"),
            (1, "LEAK-host.example.org"),
        ] {
            d["grounding"][g]["kind"] = json!("http.fetch");
            d["grounding"][g]["host"] = json!(host);
            d["grounding"][g]["route"] = json!(EMAIL);
        }
        let d: Diff = serde_json::from_value(d).unwrap();
        let policy =
            json!({"outcome": "deny", "fired": [{"name": "LEAK-rule.", "action": "deny"}]});
        let s = summary(&d, Some(&policy), &["*.example.com", "api.example.net"]);
        // Not `.kinds[].kind`, `.causes[].kind` (a marker is no deployed
        // kind) nor `.grounding[].method` (no route method): the PR's code
        // chooses them (N1).
        let allowed = [
            ".fork",
            ".base.branch",
            ".code.before[].kind",
            ".code.before[].code_hash",
            ".code.after[].kind",
            ".code.after[].code_hash",
            ".kinds[].code",
            ".causes[].input",
            ".errors.items[].kind",
            ".errors.items[].error_code",
        ];
        let mut shown = Vec::new();
        for (n, path) in paths.iter().enumerate() {
            if s.contains(&format!("LEAK{n}.")) && !allowed.contains(&path.as_str()) {
                shown.push(path);
            }
        }
        assert!(shown.is_empty(), "{shown:?} in the summary:\n{s}");
        for leak in ["alice", "/v1/", "LEAK-host"] {
            assert!(!s.contains(leak), "{leak} in the summary:\n{s}");
        }
        for want in [
            "| `http.fetch` | `(other)` |",
            "| `*.example.com` | 1 | 2 | 3 | 4 | 10.0 % |",
            "| `(no grant)` | 1 | 2 | 3 | 4 | 10.0 % |",
            "`LEAK-rule.` (`deny`)",
        ] {
            assert!(s.contains(want), "{want}:\n{s}");
        }
    }

    /// M1: an interpolated string cannot leave its inline code span.
    #[test]
    fn interpolated_strings_are_inert_inline_code() {
        assert_eq!(
            code("a`b|c\n![i](https://evil.example/p.png) @octocat\\"),
            "`ab\\|c![i](https://evil.example/p.png) @octocat`"
        );
        assert_eq!(code(" "), "(none)");
        let mut d = leaky_diff();
        d.grounding = vec![row("secret.reveal", "", "[l](https://evil.example)|x", "")];
        let s = summary(&d, None, &[]);
        assert!(
            s.contains("| `secret.reveal` | (none) | `[l](https://evil.example)\\|x` |"),
            "{s}"
        );
    }

    /// N1: a method no route may declare and a kind with no code (the
    /// target of a send to an undeployed kind) are strings the PR's code
    /// chose, e.g. a value it read in production: never shown.
    #[test]
    fn the_summary_hides_guest_chosen_methods_and_kinds() {
        // The fixture deploys `counter`.
        let mut d = leaky_diff();
        d.kinds = ["p19800101-1234", "counter"]
            .map(|kind| KindReport {
                kind: kind.into(),
                code: "absent".into(),
                ..Default::default()
            })
            .into();
        d.causes = vec![Cause {
            kind: "p19800101-1234".into(),
            input: "message hello".into(),
            origins: 1,
            consequences: 0,
            root_inputs: 1,
            samples: Vec::new(),
        }];
        d.grounding = vec![
            row("http.fetch", "19800101-1234", "a.example.com", "/"),
            row("http.fetch", "GET", "a.example.com", "/"),
        ];
        let s = summary(&d, None, &["a.example.com"]);
        assert!(!s.contains("19800101-1234"), "{s}");
        for want in [
            "| `(undeployed kind)` | `absent` |",
            "| `counter` | `absent` |",
            "- `(undeployed kind)` `message hello`: 1 origins",
            "| `http.fetch` | `(other)` | `a.example.com` |",
            "| `http.fetch` | `GET` | `a.example.com` |",
        ] {
            assert!(s.contains(want), "{want}:\n{s}");
        }
        // The full diff (pii:read readers only) keeps them.
        assert!(render(&d, None).contains("p19800101-1234"));
    }

    /// M11, L13: counts come from the totals, not from the capped lists;
    /// grounding past 10 targets says how many more, with a Live column.
    #[test]
    fn the_summary_counts_from_totals() {
        let mut d = leaky_diff();
        d.kinds = vec![KindReport {
            kind: "counter".into(),
            code: "changed".into(),
            actors_changed: 250,
            ..Default::default()
        }];
        d.errors.introduced = 30;
        d.errors.items = (0..20)
            .map(|_| ErrorItem {
                kind: "introduced".into(),
                error_code: "TURN_FAILED".into(),
                message: String::new(),
                turn_prod: None,
                turn_fork: None,
                input: String::new(),
            })
            .collect();
        let hosts: Vec<String> = (0..12).map(|i| format!("h{i:02}.example.com")).collect();
        d.grounding = hosts
            .iter()
            .map(|h| row("http.fetch", "GET", h, "/"))
            .collect();
        let grants: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let s = summary(&d, None, &grants);
        for want in [
            "| State | 250 actors changed,",
            "- `introduced`: `TURN_FAILED` × at least 20",
            "| Kind | Method | Host | Exact | Approximate | Synthetic | Live | Confidence |",
            "| `h09.example.com` |",
            "… 2 more targets",
        ] {
            assert!(s.contains(want), "{want}:\n{s}");
        }
        assert!(!s.contains("h10.example.com"), "{s}");
    }

    #[test]
    fn a_change_that_rounds_to_zero_is_not_negative() {
        assert_eq!(pct(-232.0 / 2_420_306.0), "0.0 %");
        assert_eq!(pct(0.0), "0.0 %");
        assert_eq!(pct(0.97), "97.0 %");
        assert_eq!(pct(-0.031), "-3.1 %");
    }
}
