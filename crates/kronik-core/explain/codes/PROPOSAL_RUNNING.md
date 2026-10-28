A proposal's replay runs as a job in the daemon (M10): `kronik propose --async` returns at once, and a plain `kronik propose` whose connection breaks leaves the job running. Until the job has written the diff and evaluated the policy, the proposal has the status `running`, and what needs the finished proposal answers with this code: `approve`, `promote`, `request-approval`, `diff show`, `send --fork` into the proposal's fork (MCP `send_to_fork`), and `kronik proposal wait` when its `--timeout` runs out first.

Kronik uses its own code for this, not `PROPOSAL_STALE` or `BAD_REQUEST`, because the request is right and only early: a client can wait and send it again unchanged.

Follow the job until it is done, then repeat the command:

    kronik proposal wait p-7h3k2a9c1d0e --timeout 45m

See also: `proposal`.
