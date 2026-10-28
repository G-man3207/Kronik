//! Markdown rendering of a diff (docs/design/m3-fork.md §5.11).
//! Deterministic like the JSON.

use std::fmt::Write as _;

use serde_json::Value;

use crate::diff::{ActorState, Diff, FieldDiff, KeyDiff, SqlDiff};

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
    let s = &d.summary;
    let _ = writeln!(o, "# Behavior diff: {}\n", d.fork);
    let _ = writeln!(
        o,
        "- Base: {} at LSN {}, window {}..={}",
        d.base.branch, d.base.fork_lsn, d.base.from_lsn, d.base.to_lsn
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
            a.kind,
            before.map_or("(new)", |b| b.code_hash.as_str()),
            a.code_hash,
            before.map_or(0, |b| b.schema_version),
            a.schema_version
        );
    }
    if let Some(p) = policy {
        let outcome = p.get("outcome").and_then(Value::as_str).unwrap_or("?");
        let fired: Vec<String> = p
            .get("fired")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|f| {
                let mut line = format!(
                    "{} ({})",
                    f.get("name")?.as_str()?,
                    f.get("action")?.as_str()?
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
    let _ = writeln!(
        o,
        "| Effects | exact {}, approximate {}, synthetic {} (confidence {}) |",
        num(s.exact),
        num(s.approximate),
        num(s.synthetic),
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
                k.kind,
                k.code,
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
        let _ = writeln!(o, "\n## Grounding\n");
        let _ = writeln!(
            o,
            "| Kind | Method | Host | Route | Exact | Approximate | Synthetic | Confidence |"
        );
        let _ = writeln!(o, "| --- | --- | --- | --- | --- | --- | --- | --- |");
        let mut rows: Vec<_> = d.grounding.iter().collect();
        rows.sort_by_key(|g| g.approximate + g.synthetic == 0);
        for g in rows {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                g.kind,
                g.method,
                g.host,
                g.route,
                num(g.exact),
                num(g.approximate),
                num(g.synthetic),
                pct(g.confidence)
            );
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
                "- {} {} {} {}{} ({}; {} → {})",
                i.change,
                i.kind,
                i.method,
                i.host,
                i.route,
                i.grounding,
                i.turn_prod.as_deref().unwrap_or("∅"),
                i.turn_fork.as_deref().unwrap_or("∅")
            );
            field_lines(&mut o, &i.fields);
        }
    }
    if !d.state.isolated.is_empty() || !d.state.continuous.is_empty() {
        let _ = writeln!(o, "\n## State\n");
        for st in &d.state.isolated {
            let _ = writeln!(o, "- `{}` after root LSN {}", st.actor, st.root_lsn);
            key_lines(&mut o, &st.keys, &st.sql);
        }
        if !d.state.continuous.is_empty() {
            let _ = writeln!(o, "\nFinal state (continuous replay):\n");
            actor_states(&mut o, &d.state.continuous);
        }
    }
    if d.cumulative.actors_changed > 0 {
        let _ = writeln!(o, "\n## Cumulative\n");
        let _ = writeln!(
            o,
            "{} actors drift over the window.\n",
            num(d.cumulative.actors_changed)
        );
        actor_states(&mut o, &d.cumulative.items);
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
    let sm = &d.samples;
    let cats = [
        ("Origins", &sm.origins),
        ("Consequences", &sm.consequences),
        ("Changed responses", &sm.responses_changed),
        ("Changed effects", &sm.effects_changed),
        ("Introduced errors", &sm.errors_introduced),
        ("Synthetic effects", &sm.synthetic),
    ];
    if cats.iter().any(|(_, v)| !v.is_empty()) {
        let _ = writeln!(o, "\n## Samples\n");
        for (name, ids) in cats {
            if let Some(first) = ids.first() {
                let _ = writeln!(o, "- {name}: {} (`kronik trace {first}`)", ids.len());
            }
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::{num, pct};

    #[test]
    fn thousands() {
        assert_eq!(num(0), "0");
        assert_eq!(num(999), "999");
        assert_eq!(num(10412), "10 412");
        assert_eq!(num(1234567), "1 234 567");
    }

    #[test]
    fn a_change_that_rounds_to_zero_is_not_negative() {
        assert_eq!(pct(-232.0 / 2_420_306.0), "0.0 %");
        assert_eq!(pct(0.0), "0.0 %");
        assert_eq!(pct(0.97), "97.0 %");
        assert_eq!(pct(-0.031), "-3.1 %");
    }
}
