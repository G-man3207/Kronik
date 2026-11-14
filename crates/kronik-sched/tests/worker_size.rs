//! An actor's worker is spawned in a box whenever a job reaches an idle actor,
//! so about once per turn under load. The release build's allocator (zig's,
//! in the static musl binary) serves blocks above 32 KiB with a fresh `mmap`
//! and returns them with `munmap`: a page-faulting pair of system calls and a
//! TLB shootdown per turn, which cost the release build about a tenth of its
//! throughput (docs/perf.md, "The release build against glibc and v0.4.1").
//! The worker's future must stay under that line with room for the task's
//! sender.

#[test]
fn an_actor_worker_stays_under_the_allocators_32_kib_line() {
    let size = kronik_sched::Node::worker_future_size();
    let limit = 31 * 1024;
    eprintln!("Node::worker's future: {size} bytes, limit {limit}");
    assert!(
        size < limit,
        "Node::worker's future is {size} bytes, over {limit}: a spawned worker \
         would cross the 32 KiB above which the release build maps and unmaps \
         every allocation. Box the future of a rarely taken branch on the turn \
         path (`Box::pin(...).await`) instead of awaiting it inline; \
         `RUSTC_BOOTSTRAP=1 cargo rustc --release -p kronik-sched --lib -- \
         -Zprint-type-sizes` shows which states are large."
    );
}
