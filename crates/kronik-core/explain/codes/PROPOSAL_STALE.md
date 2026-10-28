Promote first runs catch-up: the fork runs the root inputs that arrived after the proposal, in rounds, until it is at most `promote.max_gap` (2 seconds by default) behind main. Promote was aborted because catch-up did not converge within `promote.catch_up_timeout` (5 minutes by default), because the fork point is now outside the retention window, or because main's code for a kind changed since the proposal forked: a kind the proposal changes or skipped no longer runs the code main ran for it when the proposal was made, so promoting would overwrite that newer code.

Typical causes: a proposal that waited too long, for example for an approval, heavy traffic during catch-up, or another proposal for the same kind promoted (or rolled back) first.

To fix it, propose the change again, so that it is verified against recent history, and promote the new proposal soon after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"

See also: `proposal`.
