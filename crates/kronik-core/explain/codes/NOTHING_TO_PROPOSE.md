`kronik propose` skips a component when main runs its code now and ran it at the fork point too (M9). When that leaves nothing, there is no change to verify, and propose answers with this code and writes nothing: the message names each component with its kind and short code hash.

Kronik uses its own code for this, not `BAD_REQUEST`, because a program depends on telling it apart (ADR 0012, amendment of M10): the GitHub Action reports a pull request that changes no actor code, or a re-run after the promote, as a neutral check with a notice instead of a failure. The request is well formed; there is just nothing new in it.

Change a component and build it again, then propose:

    kronik propose <wasm>... --reason "..."

To replay the code main already runs, use a fork instead:

    kronik fork create --reason "..." then kronik replay <fork> --reason "..."

See also: `proposal`.
