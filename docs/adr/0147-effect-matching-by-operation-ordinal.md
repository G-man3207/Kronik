# 0147. An effect is matched by the turn's operation ordinal

- **Status:** Accepted (2026-11-15)
- **Date:** 2026-11-15

## Context

M3 replays a fork turn against the production turn with the same causal key.
The production turn records its effects in operation order. Each effect-like
host call takes the next operation ordinal from one counter per turn, shared
by `send`, `call`, `timers.schedule` and every external effect (`http.fetch`,
`foreign.http`, `crypto.*`, `secret.reveal`, `connection.send-now`), see
`m1-core.md` §3 and `m2-effects.md` §3. The ordinal is written to the
`EffectRecord` (or the message or timer) and is part of the operation's
identity: it feeds the HTTP idempotency key, a message id, a timer id and the
causal key of a called turn.

The brief specifies this matching (`Build-Brief.md:687-710`;
`Build-Brief-Original-Swedish.md:685-708`), and `kronik-fork` implements it.
The fork's gate looks up production's recording at that ordinal and grades
it:

1. **Exact:** same kind and fingerprint, compared under the recording's own
   rules (ADR 0134). The recorded result is returned.
2. **Approximate:** same kind and target (method, host and route pattern for
   HTTP), but a different fingerprint. The recorded result is reused, the
   effect is flagged approximate, and the request difference goes to the
   diff.
3. **Synthetic:** no exact or approximate match. A stub rule or a configured
   simulator (contract, neighbor, model) can answer; the default is
   `FailClosed`, which gives the guest `denied("replay: no recording")` and
   marks the turn divergent.

An effect with no recording can also be answered live (an allowlisted
replay-safe GET, `GROUNDING_LIVE`). For a foreign target in continuous replay,
the fork's copy of that actor answers instead (`GROUNDING_FORKED`, ADR 0020):
the copy serves production's exact recording when there is one, and never
uses an approximate one. A simulator answers at the call's ordinal and its
grade is synthetic, even when it reuses a recording from elsewhere (a
neighbor's exchange, say). The pair is fixed by the ordinal before the answer
is chosen.

The erased-input path (ADR 0109) and the host-redaction-failure path
(m2-effects §3) serve the recording at the ordinal without re-comparing the
request; they are exceptions to the comparison, not to ordinal matching.

`crypto.*` matches by kind and fingerprint; an unmatched one follows the
grant's in-forks mode (ADR 0112, ADR 0132). `secret.reveal` answers the
placeholder for a matching reveal. `actor.call` is re-executed; its
recording is used only for a timeout or an erased answer (ADR 0124).
`connection.send-now` is matched by causal key, ordinal, kind and
connection, but stays outside `grounding` (ADR 0116).

The route pattern replaces path segments that are decimal numbers, UUIDs,
8 or more hex characters, or a mix of letters and 6 or more digits with
`{}`. The target for approximate HTTP matching is therefore method, host and
route pattern, not the exact URL; scheme, port and query are ignored. The
fingerprint (ADR 0134) decides exact.

Nothing in the log says how an effect depends on an earlier one.
`EffectRecord` has the ordinal, kind, target, fingerprint, request, response,
status, delivery, idempotency key, error and simulator, but no edge to another
ordinal. The request is opaque bytes to the host: it cannot tell which bytes
the guest copied from an earlier response. A call whose request carries an id
from a previous call is recorded like any other call.

**Can the format carry the edge?** Not as it stands. A later log version
could add an optional `EffectRecord` field (a repeated `depends_on` ordinal,
say) under I16, but something must produce it. The host only sees opaque
request and response bytes; proving that a request byte came from an earlier
response needs provenance tracking in the runtime or a declaration in the
actor ABI. Old recordings would have no such field, so a future matcher
would still fall back to ordinal matching for them. Even then, the edge
would answer "which answer shaped this request", not "is it safe to answer
this write from another position"; deciding that would need the policy
surfaces this ADR defers. Issue #102 records the question; this ADR does not
invent the field.

The brief makes divergence visible, but neither the brief, an ADR nor the
docs said what a behavior diff shows when new code changes the order or the
count of outbound calls in a turn (issue #102). This ADR records that answer
and decides whether to replace ordinal matching with pairing by target and
fingerprint and an order-preserving sequence alignment.

## Decision

**For an external effect, the turn's operation ordinal is the only pairing
key.** The gate compares the fork's effect with production's effect at the
*same* `(causal key, ordinal)`; kind, target and fingerprint grade that pair.
The exact and approximate checks do not search other ordinals for a better
fingerprint, and the gate does not align the two effect sequences. An
opt-in simulator can answer later; the neighbor searches production's
recordings, while a contract or the model does not. A simulator's answer is
synthetic, never exact or approximate. Order and count are behavior: a call
that moves is compared at the ordinal it now takes, and one that disappears
leaves its ordinal to the call that now occupies it.

**Why it is the key.** The ordinal is the position the log already gives
every operation of the turn: a value that is total, stable and local to it.

- **Deterministic and cheap.** One lookup by the value the host already
  wrote; no similarity search whose result depends on which other
  recordings exist. Identity replay is exact and empty by construction.
- **It is the operation's identity.** The ordinal feeds the HTTP
  idempotency key, a message id, a timer id and a called turn's causal key.
  Matching at another ordinal would let one operation consume another's
  answer. A re-run must see its recorded answers in the same order (I1); a
  fork must not reach outside for a missing one, except an operator-allowed
  replay-safe GET (I7, m3-fork §2).
- **It makes order visible.** A reorder or a count change is behavior
  change. Treating the effects as a set of requests would normalize it
  away. Approximate matching is narrow, same target only, and graded, so a
  changed request at the same position still reaches policy.
- **It fails closed.** With no same-ordinal record, the fork does not look
  for a plausible answer it cannot justify. A stub, a live GET or a
  simulator must be configured; the answer is graded synthetic (or live for
  an allowlisted GET), never exact or approximate.

The grading is the existing one:

| Condition | Grade | Result reused |
| --- | --- | --- |
| same kind and fingerprint | exact | yes |
| same kind and target, other fingerprint | approximate | yes, request difference in the diff |
| no exact or approximate match; a stub or simulator answers | synthetic | that answer |
| no exact or approximate match; `FailClosed` | synthetic | `denied` (or the stored failure) |
| no recording; an allowlisted replay-safe GET | live | the live response |
| a foreign copy answers, with no exact recording | forked | the copy's answer (ADR 0020) |

The cases from issue #102 therefore behave as follows.

| New code | Matching | Behavior diff |
| --- | --- | --- |
| Two HTTP calls of the same kind to different targets swapped | Target differs at both ordinals, so no exact or approximate match | Two `changed` items. Both fork effects take the synthetic path (a live allowlisted GET would be `live` instead); with no stub, live rule or simulator the guest gets `denied`, and code that uses it may fail. Production's request is in each item's `fields.prod`. |
| Two HTTP calls to the same target swapped | Same target at both ordinals, different fingerprints | Two `changed` items, both approximate. Each call is answered with the recording at its own ordinal, i.e. with the other call's response; the diff shows the request differences but does not say the responses were crossed. |
| Two HTTP calls with the same target and fingerprint swapped | Fingerprints are equal and the calls are indistinguishable | Exact at both ordinals. There is no effect difference; if the recordings' responses differ, each call still gets the response at its ordinal, and the host cannot know the code meant the other one. |
| An effect in the `effects` section (HTTP, foreign, crypto, reveal) inserted or removed before another external effect | Every later ordinal shifts | At each shifted ordinal the fork's effect is approximate (same target, other fingerprint), synthetic (other target) or exact (identical request). The diff pairs by ordinal too: each shifted pair whose request differs is `changed`, and the extra effect is `added` (insertion) or `removed` (removal) at the tail. The item at the insertion point is the new effect paired with production's old one there, not an "inserted" label. If the kinds differ, that pair is `removed` + `added` instead. |
| An operation outside the `effects` section inserted or removed (`send`, `call`, `timers.schedule`, `connection.send-now`) | Its ordinal is consumed, so later external effects shift although no effect in the section was added or removed | The same cascade, with one ordinal left unpaired. Inserting it: the first shifted external ordinal has production only (`removed`), the paired ones whose request differs are `changed`, and the new last one is `added`. Removing it: the first re-used ordinal has the fork only (`added`), the paired ones whose request differs are `changed`, and the old last one is `removed`. For `send`, `call` and timers the message id, timer id or child causal key also changes; a `send-now` moves in `frames`. Descendants or frames can be new or missing in the diff. |

`send`, `call`, `timers.schedule` and `connection.send-now` take ordinals even
when they are not external effects, so inserting one before an HTTP call
shifts the HTTP call. Buffered connection frames (`send`, `broadcast`,
`close`) take no ordinal (ADR 0115).

A change before another external effect is therefore not reported as a pure
insertion at its position: the diff pairs by ordinal, so the shift appears in
the pairs and the extra call at the tail. If the new call is a duplicate of
the next one, the pair at that ordinal is exact, but the extra call still
appears as the tail `added`.
Likewise, a removed call does not appear in `grounding` or lower
`confidence`: grounding rows count the fork's effects. The `effects` section
shows the ordinal pairing and the tail item; its `added`, `removed` and
`changed` counts are uncapped, but `effects.items` holds at most 200 items
(`m3-fork.md` §5.5). The `removed` item carries `grounding: "live"`
because there is no fork effect, not because a live call happened.

**Policy.** Reordering and insertion are gated per target by the grounding
that the fork's effects receive. The default `payments-must-be-exact` requires
approval when any `payments.internal` target has an approximate or synthetic
effect, which covers a payment call that moved, was inserted, or received a
different request. A payment call that the new code no longer makes has no
grounding row of its own. If the ordinal now carries nothing, or a
non-payment effect, the default rules see no payment change; if it carries
another payment effect, that effect is graded and the default sees it. To
gate the removal itself:

```toml
[[rule]]
name = "external-effects-need-review"
when = "diff.effects.added + diff.effects.removed + diff.effects.changed > 0"
action = "require_approval"

[[rule]]
name = "payments-not-removed"
when = "diff.effects.items.exists(e, e.host.endsWith('payments.internal') && e.change == 'removed')"
action = "require_approval"
```

The first rule reads the uncapped counts of the diff's `effects` section,
but not per target: it reviews any target's added, changed or removed HTTP,
foreign HTTP, crypto or reveal effect.
Connection `send-now` is outside that section, in `frames`. The second names
the target, but it is best effort:

- `effects.items` is capped, so a removed item beyond the cap is missed.
- A removed item's `host` describes the production effect (there is no fork
  effect), which is what the rule reads. A payment call removed while the
  next external effect of the **same kind** takes its ordinal is not a
  `removed` item; it is a `changed` item whose `host` is that following call,
  and the payment target is only on the production side of `fields`. A
  following call of another kind, or an internal operation that takes the
  ordinal, gives a `removed` payment item, so the rule sees it.

The diff has no uncapped per-target count of production effects, so no item
rule can cover every counted mid-turn removal. Use the first rule where
completeness matters, or accept a narrow best-effort review. This gap is part
of why the matching change below waits for a schema addition. `exact` means
the same request was answered at the same ordinal; it does not order the
effect against local state writes, which a turn record does not order.

**The proposed fingerprint-first pairing and sequence alignment are
deferred, not rejected.** The direction is sound for read-only effects: a
reordered `GET /items/7` and `GET /items/9` could each take their own
recording, and an inserted call would not shift later matches. It is not
ready to replace the ordinal for writes today.

One part is available now: an operator can deny or require approval for
every approximate or synthetic effect on a write target. The default
`payments-must-be-exact` does not distinguish reads from writes; it gates
every `payments.internal` effect. The engine does not enforce that
distinction for every target because the method is only a hint and the route
semantics are the operator's. The proposed direction's stricter "a moved
write never reuses a response" is therefore a policy interpretation of
`approximate` today, and a new engine grade only after these prerequisites:

- A write's recorded response was produced at its ordinal. Reusing it for the
  same request at another position assumes the exchange did not depend on
  what happened before it. Without an edge from B to A, the log cannot show
  that it did, and the host cannot infer it from opaque request bytes.
  Sequence alignment would make that assumption for every pair it aligns.
- Two identical writes to one target are interchangeable to a fingerprint
  matcher but not to the target. The alignment has no tie-break that is
  derived from the recording; any deterministic tie-break is a new policy
  choice with its own semantics and tests.
- `exact` today means "the recording at this operation ordinal". Pairing a
  call with a recording from another ordinal would need a new label such as
  `reordered`. `Grounding` is an enum in the `kronik.diff/v1` response, so
  adding a value is a breaking change for consumers that match exhaustively;
  an optional per-item field is additive, but policies need an uncapped
  per-target count of each label, which the diff does not have.
- The effects list is capped at 200 items while the counts are not. A CEL
  rule that reads pairing labels from items could silently miss a reorder
  beyond the cap. A complete policy needs new aggregate counts.
- Alignment needs a stable objective and tie-breaks to keep `diff_hash`
  deterministic and identity replay empty, and tests for both. That is a
  design, a schema addition, a policy surface and a compatibility fixture, not
  a clarification of the current behavior.

The direction is revisited when the log can carry effect dependencies (an
additive `EffectRecord` field filled by a producer that can prove which
earlier ordinal shaped a request, with old logs falling back to ordinal
matching) or when the project accepts a policy that aligns only read-only
effects and leaves every write at its ordinal. The diff then needs additive,
uncapped per-target pairing counts before a CEL rule can gate it completely.
Until then, ordinal matching is the contract.

## Alternatives

- **Pair by target and fingerprint first, now.** It would turn the
  different-target swap into two matched answers and make an inserted read
  cheap. It also answers a moved write with a recording from a position the
  code did not execute, without a dependency edge, and redefines `exact` from
  an ordinal property to a request property. Deferred for the reasons above.
- **Align the remaining effects with an LCS/Myers sequence.** This is the
  part that makes an inserted call a pure insertion, which is useful for the
  diff's presentation. It guesses that identical or similar neighbors are the
  same operations, and two identical writes give every alignment a choice
  with different responses. It must not decide which response a write gets
  before the dependency question and a deterministic tie-break are settled.
- **Label the existing pairing as reordered/inserted/removed.** The diff
  already rebuilds a changed/added/removed view from ordinal pairs; calling a
  changed pair "reordered" would not distinguish a moved call from a changed
  request at the same position. A truthful label needs the cross-ordinal
  matching in the first alternative, and a place for it in the schema.
- **Treat every approximate match as divergence.** Approximate is the
  deliberate grade for "same target, changed request" (a changed amount, a
  scrubbed secret, a changed body). Folding it into synthetic would hide real
  changes and make the default approval rules less precise. Writes are gated
  by a policy on their targets instead; the default already requires review
  for payments.
- **Match by request bytes only, ignoring the turn.** Different root inputs
  and different turns may make identical requests for different reasons. The
  causal key keeps a recording in its own execution, and the turn is the
  scheduling unit; dropping it would let one root input's answers answer
  another.
- **Reject the direction outright.** It has a real use for read-only effects
  and for showing reorders instead of cascades. It stays recorded as deferred
  work with named prerequisites.

## Consequences

- Identity replay is exact and empty: the same code takes the same ordinals,
  and each one finds its recording. A re-run, recovery or fork keeps the
  operation's idempotency key, message id, timer id and child causal key.
- A changed order or count of outbound calls in a turn is visible as a
  behavior change. It is not normalized away by a matcher, and a fork never
  reaches the outside world to re-establish the missing answer (I7).
- A same-target permutation is graded approximate and receives the other
  call's recording. Reviewers must read the effect items' `fields` and
  policies must gate the target. The default `payments-must-be-exact` does
  for payments; other writes need their own rule. This is the known cost of
  the decision.
- A mid-turn insertion or removal cascades through every later ordinal,
  including the ids of `send`, `call` and `timers.schedule` and the pairing
  of `send-now` in `frames`. The diff may contain more changed items than the
  code change has calls. The origin is the turn whose operation sequence
  changed; its descendants' differences follow as consequences.
- A removed payment call can leave `confidence` at 1.0 and fire no default
  policy rule when the fork makes no payment effect at its ordinal. An
  operator who needs approval for absence adds a rule on `diff.effects`. The
  count rule is uncapped and sees every counted effect in this section, but
  not the target; the item rule names the target where the item says
  `removed`, is capped, and misses a same-kind successor that takes its
  ordinal.
- A per-target absence gate that is both complete and narrow needs the
  production-side target counts that this ADR defers. Until then, the
  choice is a broad external-effect gate or a narrow best-effort one.
- Old logs and old code keep their behavior: this ADR adds no log field, no
  diff field, no grounding value and no matching path. It is additive
  documentation of v0.1 to v0.5 behavior.
- Verified by the M3 replay and diff tests (identity replay, approximate
  payments, per-target grounding, the ordinal-pairing regression test that
  accompanied this ADR) and by the book and doc-surface checks. Revisit the
  decision, not the wording, when effect dependencies are recorded or when
  `kronik.diff` gets a versioned pairing section.
