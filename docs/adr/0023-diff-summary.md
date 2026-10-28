# 0023. The public diff summary

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M10: "`kronik diff show --summary` gives a short Markdown summary without
bodies and state values, intended for public PRs", tested "against a diff
with PII". A pull request comment on a public repository is readable by
anyone. The full diff (`--md`) shows response bodies and headers, state
keys and values, SQL rows, effect fields, error messages and actor names
(`kind/key`, where a key is often a user id or an e-mail address). Values
with a subject are redacted, but plain values are not, and a caller with
`pii:read` can see more (for example an effect's request body).

## Decision

The summary is built from an allow-list, never by filtering the full
Markdown (`kronik_fork::markdown::summary`, `format=summary`):

- the overview the full diff starts with: fork, window, code hashes per
  kind, policy outcome and the fired rules, the summary table and the
  per-kind table (counts only). A kind with no code before or after (the
  target of a send to a kind that is not deployed) shows as
  `(undeployed kind)`: the proposed code chose that name;
- counts of responses, effects, changed actors, drifting actors and errors,
  and the fuel and memory p99 changes, all from the diff's totals (the
  lists in the diff are capped);
- error codes with counts (`` `introduced`: `TURN_FAILED` × 3 ``), not
  messages; a count is "at least N" when the diff's error items for that
  kind were capped;
- causes as actor kind and input pattern (a route pattern the gateway
  matched, or a message or timer name, as the code declares them), with
  counts; an HTTP input without a pattern shows as `(no route)`, never its
  path;
- grounding per effect kind, method and host, with exact, approximate,
  synthetic and live counts and the confidence, the first 10 targets and
  "… N more". A method is shown only if a route may declare it (`GET`,
  `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`), else as `(other)`:
  the guest passes any string, and a fork sends nothing that would reject
  it. For `http.fetch` the host is the most specific `http:` grant
  in force that matches it: a host under a wildcard grant shows as the
  pattern (`*.example.com`), a host without a grant as `(no grant)`. Other
  kinds show the foreign actor's or the secret's name;
- a pointer to `kronik diff show <fork> --md` for the whole diff.

It never shows a URL path or route pattern of an effect, a body, a header,
a state key or value, an SQL row, an effect's fields, an error message, an
actor key, a turn's sample ids or a redaction marker, whatever the caller's
scopes and the privacy mode. An effect's route is derived from the URL the
code built at run time, and its segments can be user data (an e-mail
address, a phone number, a personal ID number), so it is left out.

Every interpolated string (kind names, code hashes, rule names, error
codes, causes, methods, hosts) is inline code with backticks, backslashes
and control characters removed and `|` escaped, so it adds no link, image,
mention, HTML or table cell.

## Alternatives

- **The full Markdown with values replaced by `…`.** A filter that misses
  one field leaks it; an allow-list cannot.
- **Only the summary table.** Too little for a review: which kinds changed,
  which targets are approximate and which errors appeared are what a
  reviewer decides on, and they hold no user data.
- **Include sample turn ids for `kronik trace`.** Harmless, but noise in a
  PR comment; the full diff has them.

## Consequences

- A PR comment shows what changed and how sure the replay is, never what
  users sent or stored. Reviewers with access use `--md` or the API.
- Grant patterns are shown, as are foreign actor and secret names: they
  are configuration, not user data. A deployment for which a grant's host
  name is confidential must not post summaries publicly. Methods and kinds
  are strings the proposed code can choose (it can put a value it read in
  production there), so only the fixed method list and deployed kinds are
  shown (`markdown::tests::the_summary_hides_guest_chosen_methods_and_kinds`).
- Tested twice: a unit test puts a marker in every string field of a diff
  with kinds, causes, errors and grounding rows and checks that the summary
  shows only the allowed fields and no URL path
  (`markdown::tests::the_summary_shows_only_allowed_fields`), and
  `crates/kronik/tests/privacy_mode.rs` checks a real diff under privacy
  mode `on` with subjects, plain values and an e-mail address in an
  effect's URL path, through the API and `kronik diff show --summary`.
