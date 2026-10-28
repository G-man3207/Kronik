//! Human output: short, in English, and ending with the exact next
//! commands. `--json` bypasses all of this.

use std::fmt::Write as _;

use kronik_api::types::{
    ActorsResponse, DeadLettersResponse, DeployResponse, DeploymentsResponse, EffectSummary,
    ForkTurnResponse, GrantResponse, GrantsResponse, HistoryResponse, InspectResponse,
    LimitsListResponse, LimitsResponse, LimitsView, OrphansResponse, Outcome, Payload,
    RevokeResponse, Route, SecretDeleteResponse, SecretResponse, SecretsResponse, TimersResponse,
    TraceNode, TraceResponse, TurnResponse, TurnSummary,
};
use kronik_core::error::ApiError;
use kronik_core::explain::{Topic, TopicKind};

use super::units;

/// What a turn response answers.
pub enum TurnContext {
    /// `kronik send` to `actor`; `rerun` is the command without `--dry-run`.
    Send { actor: String, rerun: String },
    /// `kronik dead-letters resend` of dead letter `id`.
    Resend { id: String, rerun: String },
}

/// Code, message, hint and docs of an error.
pub fn error(e: &ApiError) -> String {
    let mut out = format!("error: {}: {}\n", e.code, e.message);
    if let Some(hint) = &e.hint {
        let _ = writeln!(out, "hint:  {hint}");
    }
    let _ = writeln!(out, "docs:  {}", e.code.docs());
    out
}

pub fn deploy(r: &DeployResponse, rerun: &str, gateway: &str) -> String {
    let d = &r.deployment;
    let mut out = String::new();
    let _ = match (r.dry_run, r.unchanged) {
        (true, true) => writeln!(
            out,
            "Dry run: {} already runs {}; deploying it again changes nothing",
            d.kind, d.code_hash
        ),
        (true, false) => writeln!(
            out,
            "Dry run: {} {} (schema {}) can be deployed; nothing was written",
            d.kind, d.code_hash, d.schema_version
        ),
        (false, true) => writeln!(
            out,
            "{} already runs {}; nothing changed",
            d.kind, d.code_hash
        ),
        (false, false) => writeln!(
            out,
            "Deployed {} {} (schema {}) at lsn {}, epoch {}",
            d.kind, d.code_hash, d.schema_version, d.lsn, d.epoch
        ),
    };
    let routes: Vec<String> = d
        .routes
        .iter()
        .map(|r| format!("{} {}", r.method, r.pattern))
        .collect();
    field(&mut out, "Routes", &routes, "none");
    field(&mut out, "Capabilities", &d.capabilities, "none");
    // The API's warnings end with the exact command for each capability that
    // the manifest asks for and that has no grant yet; the commands go to
    // `Next`.
    let mut warnings = Vec::new();
    let mut grants = Vec::new();
    for w in &r.warnings {
        match w.split_once("; run: ") {
            Some((text, cmd)) => {
                warnings.push(text.to_owned());
                grants.push(cmd.to_owned());
            }
            None => warnings.push(w.clone()),
        }
    }
    field(&mut out, "Warnings", &warnings, "");
    let next_cmds = match (r.dry_run, r.unchanged) {
        (true, false) => [vec![rerun.to_owned()], grants].concat(),
        (_, true) => [grants, vec!["kronik actors list".to_owned()]].concat(),
        (false, false) => {
            let mut cmds = grants;
            cmds.extend(d.routes.first().map(|r| curl(r, gateway)));
            cmds.push(format!(
                "kronik send {}/<key> <name> --reason \"...\"",
                d.kind
            ));
            cmds.push(format!("kronik history {}/<key>", d.kind));
            cmds
        }
    };
    out.push_str(&next(&next_cmds));
    out
}

/// A curl command for a route, with `{param}` shown as `<param>`.
fn curl(route: &Route, gateway: &str) -> String {
    let url = format!(
        "'http://{gateway}{}'",
        route.pattern.replace('{', "<").replace('}', ">")
    );
    match route.method.as_str() {
        "GET" => format!("curl {url}"),
        "HEAD" => format!("curl -I {url}"),
        method => format!("curl -X {method} {url}"),
    }
}

pub fn turn(t: &TurnResponse, ctx: &TurnContext) -> String {
    let mut out = String::new();
    let Some(outcome) = &t.outcome else {
        let (what, rerun) = match ctx {
            TurnContext::Send { rerun, .. } => ("the message is valid; nothing was sent", rerun),
            TurnContext::Resend { rerun, .. } => {
                ("the dead letter can be resent; nothing was sent", rerun)
            }
        };
        let _ = writeln!(out, "Dry run: {what}");
        out.push_str(&next(std::slice::from_ref(rerun)));
        return out;
    };
    let id = t.turn_id.as_deref().unwrap_or("-");
    let committed = outcome.kind == "committed";
    let _ = match ctx {
        TurnContext::Send { actor, .. } => {
            writeln!(out, "Turn {id} {} on {actor}", verb(&outcome.kind))
        }
        TurnContext::Resend { id: dead, .. } => writeln!(
            out,
            "Resent {dead} as turn {id}, which {}",
            verb(&outcome.kind)
        ),
    };
    if let Some(reply) = &t.reply {
        field(&mut out, "Reply", &payload_lines(&reply.body), "");
    }
    if committed {
        let cmds = match ctx {
            TurnContext::Send { actor, .. } => vec![
                format!("kronik history {actor}"),
                format!("kronik actors inspect {actor}"),
            ],
            TurnContext::Resend { .. } => vec!["kronik dead-letters list".to_owned()],
        };
        out.push_str(&next(&cmds));
        return out;
    }
    field(&mut out, "Error", &[failure(outcome)], "");
    field(
        &mut out,
        "Dead letter",
        &[format!("{id}: fix the cause, then resend it")],
        "",
    );
    let mut cmds = Vec::new();
    if let TurnContext::Send { .. } = ctx {
        cmds.push(format!("kronik dead-letters resend {id} --reason \"...\""));
    }
    if let Some(code) = &outcome.error_code {
        cmds.push(format!("kronik explain {code}"));
    }
    cmds.push(match ctx {
        TurnContext::Send { actor, .. } => format!("kronik history {actor}"),
        TurnContext::Resend { .. } => "kronik dead-letters list".to_owned(),
    });
    out.push_str(&next(&cmds));
    out
}

/// How a turn ended, as a verb phrase.
fn verb(kind: &str) -> &str {
    match kind {
        "committed" => "committed",
        "rejected" => "was rejected",
        "failed" => "failed",
        "trap" => "trapped",
        "fuel_exhausted" => "ran out of fuel",
        "memory_limit" => "hit the memory limit",
        "effect_outcome_unknown" => "has an uncertain effect outcome",
        other => other,
    }
}

/// `CODE: message` of a failed outcome.
fn failure(o: &Outcome) -> String {
    match (&o.error_code, &o.message) {
        (Some(code), Some(m)) => format!("{code}: {m}"),
        (Some(code), None) => code.clone(),
        (None, Some(m)) => m.clone(),
        (None, None) => verb(&o.kind).to_owned(),
    }
}

pub fn actors(r: &ActorsResponse, more: &str) -> String {
    if r.actors.is_empty() {
        let mut out = String::from("No actors yet; an actor appears with its first turn.\n");
        out.push_str(&next(&[
            "kronik deploy <wasm> --reason \"...\"".to_owned(),
            "kronik send <kind/key> <name> --reason \"...\"".to_owned(),
        ]));
        return out;
    }
    let rows = r
        .actors
        .iter()
        .map(|a| {
            vec![
                format!("{}/{}", a.kind, a.key),
                a.schema_version.to_string(),
                a.turns.to_string(),
                a.last_turn_id.clone(),
                if a.sql { "yes" } else { "no" }.to_owned(),
            ]
        })
        .collect();
    let mut out = table(&["ACTOR", "SCHEMA", "TURNS", "LAST TURN", "SQL"], rows);
    let mut cmds = Vec::new();
    if let Some(a) = r.actors.first() {
        cmds.push(format!("kronik actors inspect {}/{}", a.kind, a.key));
        cmds.push(format!("kronik history {}/{}", a.kind, a.key));
    }
    if let Some(after) = &r.next {
        cmds.push(format!("{more} --after {after}"));
    }
    out.push_str(&next(&cmds));
    out
}

pub fn inspect(r: &InspectResponse) -> String {
    let a = &r.actor;
    let actor = format!("{}/{}", a.kind, a.key);
    let mut out = String::new();
    let turns = if a.turns == 1 { "turn" } else { "turns" };
    field8(
        &mut out,
        "Actor",
        &[format!(
            "{actor} (schema {}, {} {turns}, last turn {})",
            a.schema_version, a.turns, a.last_turn_id
        )],
    );
    let mut state: Vec<String> = r
        .state
        .iter()
        .map(|s| {
            let mut line = format!("{} = {}  (lsn {}", s.key, value(&s.value), s.lsn);
            if let Some(subject) = &s.subject {
                let _ = write!(line, ", subject {subject}");
            }
            line.push(')');
            line
        })
        .collect();
    if state.is_empty() {
        state.push("(none)".to_owned());
    }
    field8(&mut out, "State", &state);
    if let Some(sql) = &r.sql {
        let mut tables: Vec<String> = sql
            .tables
            .iter()
            .map(|t| {
                let rows = if t.rows == 1 { "row" } else { "rows" };
                format!("{}: {} {rows}", t.name, t.rows)
            })
            .collect();
        if tables.is_empty() {
            tables.push("(no tables)".to_owned());
        }
        field8(&mut out, "SQL", &tables);
    }
    out.push_str(&next(&[
        format!("kronik history {actor}"),
        format!("kronik actors timers {actor}"),
    ]));
    out
}

pub fn history(actor: &str, r: &HistoryResponse, limit: Option<u32>) -> String {
    if r.turns.is_empty() {
        return format!("{actor} has no turns.\n");
    }
    let rows = r
        .turns
        .iter()
        .map(|t| {
            vec![
                t.turn_id.clone(),
                t.input.kind.clone(),
                clip(&t.input.summary, 40),
                clip(&outcome(&t.outcome), 60),
                clip(&changes(t), 40),
                t.code_hash.clone(),
            ]
        })
        .collect();
    let mut out = table(
        &["TURN", "TYPE", "INPUT", "OUTCOME", "CHANGES", "CODE"],
        rows,
    );
    // An HTTP effect's target is its request; a denied one has no request.
    let effects: Vec<Vec<String>> = r
        .turns
        .iter()
        .flat_map(|t| {
            t.effects.iter().map(move |e| {
                vec![
                    t.turn_id.clone(),
                    e.kind.clone(),
                    clip(e.request.as_ref().unwrap_or(&e.target), 60),
                    e.delivery.clone().unwrap_or_else(|| "-".to_owned()),
                    e.status.clone(),
                    clip(e.error.as_deref().unwrap_or("-"), 60),
                ]
            })
        })
        .collect();
    if !effects.is_empty() {
        out.push('\n');
        out.push_str(&table(
            &["TURN", "EFFECT", "TARGET", "DELIVERY", "STATUS", "ERROR"],
            effects,
        ));
    }
    // A denied effect's hint is the exact command that grants it.
    let mut cmds: Vec<String> = Vec::new();
    for hint in r
        .turns
        .iter()
        .flat_map(|t| t.effects.iter().filter_map(|e| e.hint.clone()))
    {
        if !cmds.contains(&hint) {
            cmds.push(hint);
        }
    }
    if let Some(before) = r.next {
        let mut more = format!("kronik history {actor} --before {before}");
        if let Some(l) = limit {
            let _ = write!(more, " --limit {l}");
        }
        cmds.push(more);
    }
    if r.turns.iter().any(|t| t.outcome.kind != "committed") {
        cmds.push("kronik dead-letters list".to_owned());
    }
    if cmds.is_empty() {
        cmds.push(format!("kronik actors inspect {actor}"));
    }
    out.push_str(&next(&cmds));
    out
}

fn outcome(o: &Outcome) -> String {
    if o.kind == "committed" {
        "committed".to_owned()
    } else {
        format!("{} ({})", verb(&o.kind), failure(o))
    }
}

/// The effects of a turn as table rows: effect, target, delivery class,
/// status and the guest's error.
fn effect_rows(effects: &[EffectSummary]) -> Vec<Vec<String>> {
    effects
        .iter()
        .map(|e| {
            vec![
                e.kind.clone(),
                e.target.clone(),
                e.delivery.clone().unwrap_or_else(|| "-".to_owned()),
                // A fork effect also says how it was answered (M12).
                match (&e.grounding, &e.simulator) {
                    (Some(g), Some(s)) => format!("{} ({g}: {s})", e.status),
                    (Some(g), None) => format!("{} ({g})", e.status),
                    _ => e.status.clone(),
                },
                clip(e.error.as_deref().unwrap_or("-"), 60),
            ]
        })
        .collect()
}

/// A turn run in a fork (`kronik send --fork`).
pub fn fork_turn(t: &ForkTurnResponse, actor: &str) -> String {
    let mut out = format!(
        "Turn {} {} on {actor} in fork {}\n",
        t.turn_id,
        verb(&t.outcome.kind),
        t.fork
    );
    if let Some(reply) = &t.reply {
        field(&mut out, "Reply", &payload_lines(&reply.body), "");
    }
    if t.outcome.kind != "committed" {
        field(&mut out, "Error", &[failure(&t.outcome)], "");
    }
    if !t.effects.is_empty() {
        out.push('\n');
        out.push_str(&table(
            &["EFFECT", "TARGET", "DELIVERY", "STATUS", "ERROR"],
            effect_rows(&t.effects),
        ));
    }
    out.push_str(&next(&[
        format!("kronik diff show {}", shell_quote(&t.fork)),
        "kronik fork list".to_owned(),
    ]));
    out
}

/// One turn of a causal tree on one line.
fn trace_line(turn_id: &str, actor: Option<&str>, input: &str, o: &Outcome) -> String {
    let actor = actor.map(|a| format!("  {a}")).unwrap_or_default();
    format!(
        "{turn_id}{actor}  {}  {}",
        clip(input, 50),
        clip(&outcome(o), 60)
    )
}

/// `kronik trace`: the root input, the turns from it down to the traced
/// one, and what that one caused, as a tree.
pub fn trace(r: &TraceResponse) -> String {
    let mut out = format!("Trace of {} on {}\n", r.turn.turn_id, r.actor);
    if let Some(root) = &r.root {
        let _ = writeln!(
            out,
            "Root     {} {} at lsn {} (root id {})",
            root.input.kind,
            root.input.summary,
            root.lsn,
            clip(&root.root_id, 13)
        );
    }
    out.push('\n');
    let summary = |t: &TurnSummary| format!("{} {}", t.input.kind, t.input.summary);
    let prefix = |depth: usize| match depth {
        0 => String::new(),
        d => format!("{}└─ ", "   ".repeat(d - 1)),
    };
    for (depth, t) in r.ancestors.iter().enumerate() {
        let _ = writeln!(
            out,
            "{}{}",
            prefix(depth),
            trace_line(&t.turn_id, None, &summary(t), &t.outcome)
        );
    }
    let depth = r.ancestors.len();
    let _ = writeln!(
        out,
        "{}{}   <- this turn",
        prefix(depth),
        trace_line(
            &r.turn.turn_id,
            Some(&r.actor),
            &summary(&r.turn),
            &r.turn.outcome
        )
    );
    tree(&mut out, &r.descendants, &"   ".repeat(depth));
    if r.truncated {
        out.push_str("… more than 1000 turns follow from it; the tree stops here\n");
    }
    out.push_str(&next(&[format!("kronik history {}", r.actor)]));
    out
}

fn tree(out: &mut String, nodes: &[TraceNode], indent: &str) {
    for (i, n) in nodes.iter().enumerate() {
        let last = i + 1 == nodes.len();
        let _ = writeln!(
            out,
            "{indent}{}{}",
            if last { "└─ " } else { "├─ " },
            trace_line(
                &n.turn_id,
                Some(&n.actor),
                &format!("{} {}", n.input.kind, n.input.summary),
                &n.outcome
            )
        );
        let deeper = format!("{indent}{}", if last { "   " } else { "│  " });
        tree(out, &n.children, &deeper);
    }
}

/// What a turn changed, briefly.
fn changes(t: &TurnSummary) -> String {
    let mut parts: Vec<String> = t
        .writes
        .iter()
        .map(|w| {
            let erased = if w.erased { " [erased]" } else { "" };
            format!("{} {}{erased}", w.op, w.key)
        })
        .collect();
    match t.messages.len() {
        0 => {}
        1 => parts.push(format!("message to {}", t.messages[0].to)),
        n => parts.push(format!("{n} messages")),
    }
    match t.sql_changes {
        0 => {}
        1 => parts.push("1 SQL change".to_owned()),
        n => parts.push(format!("{n} SQL changes")),
    }
    match t.effects.len() {
        0 => {}
        1 => parts.push("1 effect".to_owned()),
        n => parts.push(format!("{n} effects")),
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(", ")
    }
}

/// `full` is `Some(limit)` when the page is full, so more may follow.
pub fn dead_letters(r: &DeadLettersResponse, full: Option<Option<u32>>) -> String {
    if r.dead_letters.is_empty() {
        return "No dead letters.\n".to_owned();
    }
    let rows = r
        .dead_letters
        .iter()
        .map(|d| {
            vec![
                d.id.clone(),
                d.actor.clone(),
                clip(&format!("{} {}", d.input.kind, d.input.summary), 40),
                clip(&format!("{}: {}", d.error_code, d.message), 60),
                d.resent_as.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();
    let mut out = table(&["ID", "ACTOR", "INPUT", "ERROR", "RESENT AS"], rows);
    let mut cmds = Vec::new();
    if let Some(d) = r.dead_letters.iter().find(|d| d.resent_as.is_none()) {
        cmds.push(format!(
            "kronik dead-letters resend {} --reason \"...\"",
            d.id
        ));
        cmds.push(format!("kronik explain {}", d.error_code));
    }
    if let (Some(limit), Some(last)) = (full, r.dead_letters.last()) {
        let mut more = format!("kronik dead-letters list --after {}", last.id);
        if let Some(l) = limit {
            let _ = write!(more, " --limit {l}");
        }
        cmds.push(more);
    }
    out.push_str(&next(&cmds));
    out
}

pub fn deployments(r: &DeploymentsResponse) -> String {
    let Some(last) = r.deployments.last() else {
        let mut out = String::from("No deployments yet.\n");
        out.push_str(&next(&["kronik deploy <wasm> --reason \"...\"".to_owned()]));
        return out;
    };
    let rows = r
        .deployments
        .iter()
        .map(|d| {
            vec![
                d.epoch.to_string(),
                d.lsn.to_string(),
                d.cause.clone(),
                d.kinds
                    .iter()
                    .map(|k| format!("{} {}", k.kind, k.code_hash))
                    .collect::<Vec<_>>()
                    .join(", "),
                d.token_id.clone(),
                clip(&d.reason, 40),
            ]
        })
        .collect();
    let mut out = table(&["EPOCH", "LSN", "CAUSE", "CODE", "BY", "REASON"], rows);
    // The first deployment has nothing before it to roll back to.
    let cmds = if r.deployments.len() > 1 {
        vec![format!("kronik rollback {} --reason \"...\"", last.epoch)]
    } else {
        vec!["kronik actors list".to_owned()]
    };
    out.push_str(&next(&cmds));
    out
}

pub fn grant(r: &GrantResponse, rerun: &str) -> String {
    let g = &r.grant;
    let mut out = String::new();
    let _ = if r.dry_run {
        writeln!(
            out,
            "Dry run: {} can be granted {} at epoch {}; nothing was written",
            g.kind, g.capability, g.epoch
        )
    } else {
        writeln!(
            out,
            "Granted {} to {} at lsn {}, epoch {}",
            g.capability, g.kind, g.lsn, g.epoch
        )
    };
    if g.capability.starts_with("http:") {
        field(&mut out, "Delivery", &[delivery(g.delivery.as_deref())], "");
        field(
            &mut out,
            "Rate",
            &[g.rate.clone().unwrap_or_else(|| "no limit".to_owned())],
            "",
        );
    }
    let cmds = if r.dry_run {
        vec![rerun.to_owned()]
    } else {
        vec![
            format!("kronik grants list --kind {}", shell_quote(&g.kind)),
            format!(
                "kronik revoke {} {} --reason \"...\"",
                shell_quote(&g.kind),
                shell_quote(&g.capability)
            ),
        ]
    };
    out.push_str(&next(&cmds));
    out
}

/// An `http:` grant's delivery class; none means the method decides.
fn delivery(d: Option<&str>) -> String {
    d.map_or_else(
        || "by method: replay-safe for GET, HEAD and OPTIONS, unsafe otherwise".to_owned(),
        str::to_owned,
    )
}

pub fn revoke(r: &RevokeResponse, rerun: &str) -> String {
    let v = &r.revoked;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: {} can be revoked from {} at epoch {}; nothing was written",
            v.capability, v.kind, v.epoch
        );
        out.push_str(&next(&[rerun.to_owned()]));
    } else {
        let _ = writeln!(
            out,
            "Revoked {} from {} at lsn {}, epoch {}",
            v.capability, v.kind, v.lsn, v.epoch
        );
        out.push_str(&next(&[format!(
            "kronik grants list --kind {}",
            shell_quote(&v.kind)
        )]));
    }
    out
}

pub fn grants(r: &GrantsResponse) -> String {
    let Some(first) = r.grants.first() else {
        let mut out = String::from("No grants: every external effect is denied.\n");
        out.push_str(&next(&[
            "kronik grant <kind> <capability> --reason \"...\"".to_owned(),
        ]));
        return out;
    };
    let rows = r
        .grants
        .iter()
        .map(|g| {
            let http = g.capability.starts_with("http:");
            vec![
                g.kind.clone(),
                g.capability.clone(),
                match (&g.delivery, http) {
                    (Some(d), _) => d.clone(),
                    (None, true) => "by method".to_owned(),
                    (None, false) => "-".to_owned(),
                },
                g.rate.clone().unwrap_or_else(|| "-".to_owned()),
                g.epoch.to_string(),
                clip(&g.reason, 40),
            ]
        })
        .collect();
    let mut out = table(
        &["KIND", "CAPABILITY", "DELIVERY", "RATE", "EPOCH", "REASON"],
        rows,
    );
    out.push_str(&next(&[format!(
        "kronik revoke {} {} --reason \"...\"",
        shell_quote(&first.kind),
        shell_quote(&first.capability)
    )]));
    out
}

pub fn limits_set(r: &LimitsResponse, rerun: &str) -> String {
    let l = &r.limits;
    let epoch = l.epoch.unwrap_or_default();
    let mut out = String::new();
    let _ = if r.dry_run {
        writeln!(
            out,
            "Dry run: {} would get these limits at epoch {epoch}; nothing was written",
            l.kind
        )
    } else {
        writeln!(
            out,
            "Set the limits of {} at lsn {}, epoch {epoch}",
            l.kind,
            l.lsn.unwrap_or_default()
        )
    };
    for (label, value) in limit_values(l) {
        let _ = writeln!(out, "  {label:<18}{value}");
    }
    let cmds = if r.dry_run {
        vec![rerun.to_owned()]
    } else {
        vec![format!(
            "kronik limits show --kind {}",
            shell_quote(&l.kind)
        )]
    };
    out.push_str(&next(&cmds));
    out
}

/// Every limit, labelled, in human units.
fn limit_values(l: &LimitsView) -> [(&'static str, String); 7] {
    [
        ("Fuel", l.fuel.to_string()),
        ("Memory", units::size(l.memory_bytes)),
        ("Message size", units::size(l.message_bytes)),
        ("State value size", units::size(l.state_value_bytes)),
        ("SQL size", units::size(l.sql_bytes_per_actor)),
        ("Effect timeout", units::duration(l.effect_timeout_ms)),
        ("Effect response", units::size(l.effect_response_bytes)),
    ]
}

pub fn limits(r: &LimitsListResponse) -> String {
    let Some(first) = r.limits.first() else {
        let mut out = String::from("No actor types yet; limits apply per actor type.\n");
        out.push_str(&next(&["kronik deploy <wasm> --reason \"...\"".to_owned()]));
        return out;
    };
    let rows = r
        .limits
        .iter()
        .map(|l| {
            let mut row = vec![l.kind.clone()];
            row.extend(limit_values(l).into_iter().map(|(_, v)| v));
            row
        })
        .collect();
    let mut out = table(
        &[
            "KIND",
            "FUEL",
            "MEMORY",
            "MESSAGE",
            "STATE VALUE",
            "SQL",
            "EFFECT TIMEOUT",
            "EFFECT RESPONSE",
        ],
        rows,
    );
    out.push_str(&next(&[format!(
        "kronik limits set {} --fuel <n> --reason \"...\"",
        shell_quote(&first.kind)
    )]));
    out
}

pub fn secret_set(name: &str, r: &SecretResponse, rerun: &str) -> String {
    let mut out = String::new();
    let Some(s) = &r.secret else {
        let _ = writeln!(
            out,
            "Dry run: secret {name} can be stored; nothing was written"
        );
        out.push_str(&next(&[format!("{rerun}   (value on stdin)")]));
        return out;
    };
    let _ = writeln!(out, "Stored secret {}, version {}", s.name, s.version);
    field(
        &mut out,
        "Version hash",
        std::slice::from_ref(&s.version_hash),
        "",
    );
    out.push_str(&next(&[
        format!(
            "kronik grant <kind> {} --reason \"...\"",
            shell_quote(&format!("secret:{}", s.name))
        ),
        "kronik secret list".to_owned(),
    ]));
    out
}

pub fn secrets(r: &SecretsResponse) -> String {
    let Some(first) = r.secrets.first() else {
        let mut out = String::from("No secrets.\n");
        out.push_str(&next(&[
            "kronik secret set <name> --reason \"...\"   (value on stdin)".to_owned(),
        ]));
        return out;
    };
    let rows = r
        .secrets
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                s.version.to_string(),
                s.version_hash.clone(),
                units::utc(s.created_wall_ms),
            ]
        })
        .collect();
    let mut out = table(&["NAME", "VERSION", "VERSION HASH", "CREATED"], rows);
    out.push_str(&next(&[format!(
        "kronik grant <kind> {} --reason \"...\"",
        shell_quote(&format!("secret:{}", first.name))
    )]));
    out
}

pub fn secret_deleted(r: &SecretDeleteResponse, rerun: &str) -> String {
    let d = &r.deleted;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: secret {} can be deleted; nothing was written",
            d.name
        );
        out.push_str(&next(&[rerun.to_owned()]));
    } else {
        let versions = if d.versions == 1 {
            "version"
        } else {
            "versions"
        };
        let _ = writeln!(out, "Deleted secret {}: {} {versions}", d.name, d.versions);
        out.push_str(&next(&["kronik secret list".to_owned()]));
    }
    out
}

pub fn orphans(r: &OrphansResponse, all: bool) -> String {
    if r.orphans.is_empty() {
        if all {
            return "No orphaned changes.\n".to_owned();
        }
        let mut out = String::from("No unresolved orphaned changes.\n");
        out.push_str(&next(&["kronik history --orphans --all".to_owned()]));
        return out;
    }
    let rows = r
        .orphans
        .iter()
        .map(|o| {
            vec![
                o.actor.clone(),
                o.turn_id.clone(),
                o.caller.clone(),
                o.caller_turn_id.clone(),
                o.compensation
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |c| c.state.replace('_', " ")),
                o.resolved_turn_id.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();
    let mut out = table(
        &[
            "ACTOR",
            "TURN",
            "CALLER",
            "CALLER TURN",
            "COMPENSATION",
            "RESOLVED BY",
        ],
        rows,
    );
    let mut cmds = Vec::new();
    if let Some(o) = r.orphans.iter().find(|o| o.resolved_turn_id.is_none()) {
        cmds.push(format!("kronik history {}", o.actor));
    }
    if r.orphans.iter().any(|o| {
        o.compensation
            .as_ref()
            .is_some_and(|c| c.state == "dead_letter")
    }) {
        cmds.push("kronik dead-letters list".to_owned());
    }
    if cmds.is_empty() {
        cmds.push(format!("kronik history {}", r.orphans[0].actor));
    }
    out.push_str(&next(&cmds));
    out
}

pub fn timers(actor: &str, r: &TimersResponse) -> String {
    if r.timers.is_empty() {
        let mut out = format!("{actor} has no pending timers.\n");
        out.push_str(&next(&[format!("kronik history {actor}")]));
        return out;
    }
    let rows = r
        .timers
        .iter()
        .map(|t| vec![t.id.clone(), units::utc(t.due_ms), t.name.clone()])
        .collect();
    let mut out = table(&["ID", "DUE", "MESSAGE"], rows);
    out.push_str(&next(&[format!("kronik history {actor}")]));
    out
}

pub fn topics(topics: &[Topic]) -> String {
    let mut out = String::new();
    for (kind, heading) in [
        (TopicKind::Concept, "Concepts"),
        (TopicKind::Guide, "Guides"),
        (TopicKind::ErrorCode, "Error codes"),
    ] {
        let _ = writeln!(out, "{heading}");
        let rows = topics
            .iter()
            .filter(|t| t.kind == kind)
            .map(|t| {
                let mut row = vec![format!("  {}", t.name)];
                if let Some(status) = t.http_status {
                    row.push(status.to_string());
                }
                row.push(t.title.to_owned());
                row
            })
            .collect();
        out.push_str(&table_rows(rows));
    }
    out.push_str(&next(&["kronik explain <topic>".to_owned()]));
    out
}

/// The lines of a payload: its text, or a note about binary bytes.
fn payload_lines(p: &Payload) -> Vec<String> {
    const MAX_LINES: usize = 20;
    match &p.text {
        Some(t) if t.is_empty() => vec!["(empty)".to_owned()],
        Some(t) => {
            let lines: Vec<&str> = t.lines().collect();
            let mut out: Vec<String> = lines.iter().take(MAX_LINES).map(|l| clip(l, 200)).collect();
            if lines.len() > MAX_LINES {
                out.push(format!(
                    "… {} more lines; --json shows all of it",
                    lines.len() - MAX_LINES
                ));
            }
            out
        }
        None => vec![format!(
            "({} bytes, not UTF-8; --json shows them as base64)",
            base64_len(p)
        )],
    }
}

/// A state value on one line.
fn value(p: &Payload) -> String {
    match &p.text {
        Some(t) => clip(t, 60),
        None => format!("<{} bytes>", base64_len(p)),
    }
}

fn base64_len(p: &Payload) -> usize {
    p.base64.as_deref().map_or(0, |b| {
        let pad = b.bytes().rev().take_while(|&c| c == b'=').count();
        (b.len() / 4 * 3).saturating_sub(pad)
    })
}

/// Shortens text to `max` characters on one line.
pub fn clip(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= max {
        flat
    } else {
        let mut cut: String = flat.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

/// Quotes a word for a POSIX shell when it needs it.
pub fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b));
    if plain {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// `Next` and the commands, one per line, aligned like the brief's sample
/// output.
pub(crate) fn next(cmds: &[String]) -> String {
    let mut out = String::new();
    for (i, cmd) in cmds.iter().enumerate() {
        let label = if i == 0 { "Next" } else { "" };
        let _ = writeln!(out, "{label:<8} {cmd}");
    }
    out
}

/// An indented field with one value per line, or `empty` (nothing if
/// `empty` is "") when there are none.
pub(crate) fn field(out: &mut String, label: &str, values: &[String], empty: &str) {
    if values.is_empty() {
        if !empty.is_empty() {
            let _ = writeln!(out, "  {label:<14}{empty}");
        }
        return;
    }
    for (i, v) in values.iter().enumerate() {
        let label = if i == 0 { label } else { "" };
        let _ = writeln!(out, "  {label:<14}{v}");
    }
}

/// A top-level field in the `Next` column layout.
fn field8(out: &mut String, label: &str, values: &[String]) {
    for (i, v) in values.iter().enumerate() {
        let label = if i == 0 { label } else { "" };
        let _ = writeln!(out, "{label:<8} {v}");
    }
}

/// A table with a header; columns are separated by two spaces.
pub(super) fn table(header: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut all = vec![header.iter().map(|h| (*h).to_owned()).collect()];
    all.extend(rows);
    table_rows(all)
}

fn table_rows(rows: Vec<Vec<String>>) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in &rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i + 1 < row.len() {
                let _ = write!(line, "{cell:<w$}  ", w = widths[i]);
            } else {
                line.push_str(cell);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_what_the_shell_needs() {
        assert_eq!(shell_quote("counter/a"), "counter/a");
        assert_eq!(shell_quote("./dist/x.wasm"), "./dist/x.wasm");
        assert_eq!(shell_quote("first deploy"), "'first deploy'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn clips_to_one_line() {
        assert_eq!(clip("a\nb", 10), "a b");
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip("äöü", 3), "äöü");
    }

    #[test]
    fn tables_align_columns() {
        let t = table(
            &["A", "BB"],
            vec![
                vec!["long cell".into(), "x".into()],
                vec!["s".into(), "".into()],
            ],
        );
        assert_eq!(t, "A          BB\nlong cell  x\ns\n");
    }

    #[test]
    fn next_aligns_commands() {
        assert_eq!(
            next(&["kronik a".into(), "kronik b".into()]),
            "Next     kronik a\n         kronik b\n"
        );
    }

    #[test]
    fn counts_base64_bytes() {
        for n in 0..10 {
            let bytes = vec![0xff_u8; n];
            let p = Payload::from_bytes(&bytes);
            assert_eq!(base64_len(&p), n);
        }
    }

    #[test]
    fn deploy_turns_capability_warnings_into_grant_commands() {
        let r = DeployResponse {
            dry_run: false,
            unchanged: false,
            deployment: kronik_api::types::Deployment {
                epoch: 3,
                lsn: 9,
                kind: "relay".into(),
                code_hash: "b3:0123456789ab".into(),
                schema_version: 0,
                routes: Vec::new(),
                capabilities: vec!["http:api.example.com".into()],
            },
            warnings: vec![
                "capability http:api.example.com is not granted; run: kronik grant relay \
                 http:api.example.com --reason '...'"
                    .into(),
            ],
        };
        let shown = deploy(&r, "unused", "127.0.0.1:8080");
        assert!(
            shown.contains("  Warnings      capability http:api.example.com is not granted\n"),
            "{shown}"
        );
        assert!(
            shown.contains("Next     kronik grant relay http:api.example.com --reason '...'\n"),
            "{shown}"
        );
    }

    #[test]
    fn history_lists_code_effects_and_the_grant_for_a_denied_one() {
        let turn = |id: &str, effects| TurnSummary {
            turn_id: id.into(),
            lsn: 7,
            logical_time_ms: 0,
            code_hash: "b3:0123456789ab".into(),
            input: kronik_api::types::InputSummary {
                kind: "message".into(),
                summary: "fetch".into(),
            },
            outcome: Outcome {
                kind: "committed".into(),
                error_code: None,
                message: None,
            },
            writes: Vec::new(),
            messages: Vec::new(),
            sql_changes: 0,
            fuel_used: 1,
            effects,
        };
        let denied = kronik_api::types::EffectSummary {
            ordinal: 0,
            kind: "http.fetch".into(),
            target: "http:api.example.com".into(),
            status: "denied".into(),
            delivery: None,
            error: Some("CAPABILITY_NOT_GRANTED: http:api.example.com".into()),
            hint: Some("kronik grant billing http:api.example.com --reason '...'".into()),
            request: None,
            grounding: None,
            simulator: None,
        };
        let sent = kronik_api::types::EffectSummary {
            status: "ok".into(),
            delivery: Some("idempotency-keyed".into()),
            error: None,
            hint: None,
            request: Some("POST api.example.com/hooks/acme".into()),
            ..denied.clone()
        };
        let r = HistoryResponse {
            turns: vec![
                turn("main:9", vec![sent]),
                turn("main:8", vec![denied.clone()]),
                turn("main:7", vec![denied]),
            ],
            next: None,
        };
        let shown = history("billing/a", &r, None);
        let lines: Vec<String> = shown
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        for want in [
            "TURN TYPE INPUT OUTCOME CHANGES CODE",
            "main:9 message fetch committed 1 effect b3:0123456789ab",
            "TURN EFFECT TARGET DELIVERY STATUS ERROR",
            "main:9 http.fetch POST api.example.com/hooks/acme idempotency-keyed ok -",
            "main:8 http.fetch http:api.example.com - denied CAPABILITY_NOT_GRANTED: http:api.example.com",
        ] {
            assert!(lines.iter().any(|l| l == want), "{want}: {shown}");
        }
        assert!(
            shown.ends_with("Next     kronik grant billing http:api.example.com --reason '...'\n"),
            "the hint once: {shown}"
        );
    }

    #[test]
    fn history_marks_writes_of_erased_subjects() {
        let write = |key: &str, subject: &str, erased| kronik_api::types::WriteSummary {
            op: "set".into(),
            key: key.into(),
            subject: Some(subject.into()),
            erased,
        };
        let t = TurnSummary {
            turn_id: "main:9".into(),
            lsn: 9,
            logical_time_ms: 0,
            code_hash: "b3:0123456789ab".into(),
            input: kronik_api::types::InputSummary {
                kind: "message".into(),
                summary: "subject from operator".into(),
            },
            outcome: Outcome {
                kind: "committed".into(),
                error_code: None,
                message: None,
            },
            writes: vec![write("s", "user:1", true), write("t", "user:2", false)],
            messages: Vec::new(),
            sql_changes: 0,
            fuel_used: 1,
            effects: Vec::new(),
        };
        assert_eq!(changes(&t), "set s [erased], set t");
    }
}
