//! How many Wasm instances a daemon's pool and a replay's pool have room
//! for. A turn holds an instance for as long as it runs. The node's turns
//! are bounded by its worker permits, but a replay runs the callee of a
//! `call` inside the caller's task while the caller keeps its instance, so a
//! chain of calls holds an instance per link. A pool sized by the replay's
//! workers alone ran out at the first replayed call, and the fork's turn
//! failed as a divergence.

/// The default number of turns a daemon runs at once (ADR 0140): 8 per CPU
/// it may use, at least 8 and at most 64.
pub fn concurrency_for(cpus: usize) -> usize {
    cpus.saturating_mul(8).clamp(8, 64)
}

/// The CPUs this process may use (Rust's `available_parallelism`, which
/// honours the CPU affinity and a cgroup v2 CPU quota); 1 when unknown.
pub fn available_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// The default number of isolated replay workers: one per CPU, at most 16.
pub fn replay_workers_for(cpus: usize) -> usize {
    cpus.clamp(1, 16)
}

/// The instances one task of a replay may hold at once: its turn and the
/// callees of that turn's calls.
pub const REPLAY_INSTANCES_PER_TASK: usize = 8;

/// The instances a replay with `workers` isolated workers has room for on a
/// machine with `cpus` CPUs: [`REPLAY_INSTANCES_PER_TASK`] for each task that
/// runs turns, and at least a daemon's default concurrency there
/// ([`concurrency_for`]). A replay of both modes runs its continuous replay
/// next to the isolated workers, so even one worker makes two tasks.
pub fn replay_instances(workers: usize, cpus: usize) -> usize {
    workers
        .max(2)
        .saturating_mul(REPLAY_INSTANCES_PER_TASK)
        .max(concurrency_for(cpus))
}

/// The instances the pool of a daemon running `concurrency` turns at once
/// on `cpus` CPUs has room for. Its turns hold at most `concurrency` (one
/// per worker permit; a caller waiting for its callee keeps its permit).
/// Its forks, replays and previews run on the same pool without permits,
/// so it also has room for a replay with the default number of workers
/// ([`replay_instances`]), even when `--concurrency` is set lower.
pub fn node_instances(concurrency: usize, cpus: usize) -> usize {
    concurrency.max(replay_instances(replay_workers_for(cpus), cpus))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `concurrency_for` is pinned by `kronik serve`'s own test (ADR 0140).

    /// One worker (both modes: two tasks) has room for a call chain on a
    /// one-CPU machine, every worker has 8 instances, and no replay has
    /// fewer than the daemon's default concurrency.
    #[test]
    fn a_replay_has_eight_instances_per_task_and_at_least_the_default_concurrency() {
        assert_eq!(replay_instances(1, 1), 16);
        assert_eq!(replay_instances(2, 1), 16);
        assert_eq!(replay_instances(1, 8), 64);
        assert_eq!(replay_instances(8, 8), 64);
        assert_eq!(replay_instances(16, 16), 128);
        assert_eq!(replay_instances(16, 2), 128);
        for cpus in [1, 2, 4, 8, 16, 64] {
            for workers in [1, 2, 3, 8, 16, 64] {
                let n = replay_instances(workers, cpus);
                assert!(n >= workers * REPLAY_INSTANCES_PER_TASK, "{workers} {cpus}");
                assert!(n >= concurrency_for(cpus), "{workers} {cpus}");
            }
        }
    }

    /// At the default concurrency of 2 to 8 CPUs the daemon's pool is what
    /// it was; it grows where the default workers need more (one CPU, more
    /// than 8 CPUs), and a lower `--concurrency` does not shrink it below.
    #[test]
    fn a_daemons_pool_has_room_for_its_turns_and_its_default_replay() {
        let default = |cpus| node_instances(concurrency_for(cpus), cpus);
        assert_eq!(
            [1, 2, 4, 8, 16, 32].map(default),
            [16, 16, 32, 64, 128, 128]
        );
        assert_eq!(node_instances(1, 2), 16);
        assert_eq!(node_instances(128, 8), 128);
    }
}
