Continuous replay lets the fork evolve its own state under the new code, in production order, so that cumulative effects show up in the diff's `cumulative` part. It always runs on all root inputs, and it is the fork that catch-up continues at promote. `kronik propose --mode` selects `isolated`, `continuous` or `both`, the default.

See also: `isolated-replay`, `proposal`.
