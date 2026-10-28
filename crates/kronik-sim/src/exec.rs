//! A single-threaded deterministic executor with virtual time.
//!
//! - Every ready task is polled in an order chosen by the run's seeded RNG,
//!   so different seeds explore different interleavings and the same seed
//!   always replays the same one.
//! - Virtual time only advances when no task is ready: it jumps to the
//!   earliest timer. A run with hours of simulated latency takes milliseconds.
//! - Tasks belong to a node. Killing a node drops all of its futures at once,
//!   which is how a crash looks to the code: it just stops.
//! - Internals sit behind a `Mutex` only because `Waker` must be
//!   `Send + Sync`; there is never contention.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};

use kronik_core::env::BoxFuture;

pub type NodeId = u32;

/// The supervisor node: workload drivers, fault injectors, simulated external
/// services. Never crashed.
pub const SUPERVISOR: NodeId = 0;

struct Slot {
    node: NodeId,
    name: &'static str,
    fut: Option<BoxFuture<'static, ()>>,
    queued: bool,
}

struct Inner {
    tasks: BTreeMap<u64, Slot>,
    ready: Vec<u64>,
    timers: BTreeMap<(Duration, u64), Waker>,
    now: Duration,
    rng: ChaCha8Rng,
    next_task: u64,
    next_timer: u64,
    polls: u64,
}

/// Cloneable, `Send + Sync` handle used by wakers, sleeps and spawners.
#[derive(Clone)]
pub struct Handle(Arc<Mutex<Inner>>);

pub struct Executor {
    handle: Handle,
}

/// Why `run` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnd {
    /// No task is ready and no timer is pending.
    Quiescent,
    /// The step budget was exhausted (livelock or a very long run).
    StepLimit,
    /// The stop predicate returned true.
    Stopped,
}

impl Executor {
    pub fn new(seed: u64) -> Self {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        s[8..16].copy_from_slice(b"exec-rng");
        Self {
            handle: Handle(Arc::new(Mutex::new(Inner {
                tasks: BTreeMap::new(),
                ready: Vec::new(),
                timers: BTreeMap::new(),
                now: Duration::ZERO,
                rng: ChaCha8Rng::from_seed(s),
                next_task: 1,
                next_timer: 1,
                polls: 0,
            }))),
        }
    }

    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// Polls tasks until quiescence, `max_polls`, or `stop()` returns true
    /// (checked between polls).
    pub fn run(&self, max_polls: u64, mut stop: impl FnMut() -> bool) -> RunEnd {
        loop {
            if stop() {
                return RunEnd::Stopped;
            }
            let (id, mut fut) = {
                let mut g = self.handle.lock();
                if g.polls >= max_polls {
                    return RunEnd::StepLimit;
                }
                if g.ready.is_empty() {
                    // Wakers re-enter the lock, so wake them after releasing it.
                    let Some(due) = g.advance_time() else {
                        return RunEnd::Quiescent;
                    };
                    drop(g);
                    due.into_iter().for_each(Waker::wake);
                    continue;
                }
                let i = (g.rng.next_u64() % g.ready.len() as u64) as usize;
                let id = g.ready.swap_remove(i);
                let Some(slot) = g.tasks.get_mut(&id) else {
                    continue;
                };
                slot.queued = false;
                let Some(fut) = slot.fut.take() else { continue };
                g.polls += 1;
                (id, fut)
            };
            let waker = Waker::from(Arc::new(TaskWaker {
                id,
                handle: self.handle.clone(),
            }));
            let done = fut
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready();
            let mut g = self.handle.lock();
            if done {
                g.tasks.remove(&id);
            } else if let Some(slot) = g.tasks.get_mut(&id) {
                slot.fut = Some(fut);
            } else {
                // The task's node was killed while it was being polled.
                drop(g);
                drop(fut);
            }
        }
    }
}

impl Inner {
    /// Jumps to the earliest timer and returns the wakers of every timer due
    /// at that instant, in registration order. `None` if there is no timer.
    fn advance_time(&mut self) -> Option<Vec<Waker>> {
        let (&(deadline, _), _) = self.timers.iter().next()?;
        self.now = self.now.max(deadline);
        let mut due = Vec::new();
        while let Some(entry) = self.timers.first_entry() {
            if entry.key().0 > self.now {
                break;
            }
            due.push(entry.remove());
        }
        Some(due)
    }

    fn enqueue(&mut self, id: u64) {
        if let Some(slot) = self.tasks.get_mut(&id)
            && !slot.queued
        {
            slot.queued = true;
            self.ready.push(id);
        }
    }
}

impl Handle {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a task panicked; the run is already failing.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn spawn(&self, node: NodeId, name: &'static str, fut: BoxFuture<'static, ()>) {
        let mut g = self.lock();
        let id = g.next_task;
        g.next_task += 1;
        g.tasks.insert(
            id,
            Slot {
                node,
                name,
                fut: Some(fut),
                queued: false,
            },
        );
        g.enqueue(id);
    }

    /// Drops every task of `node`. Futures are dropped outside the lock
    /// because their destructors may wake other tasks.
    pub fn kill_node(&self, node: NodeId) -> usize {
        let dropped: Vec<Slot> = {
            let mut g = self.lock();
            let ids: Vec<u64> = g
                .tasks
                .iter()
                .filter(|(_, s)| s.node == node)
                .map(|(id, _)| *id)
                .collect();
            ids.iter().filter_map(|id| g.tasks.remove(id)).collect()
        };
        let n = dropped.len();
        drop(dropped);
        n
    }

    pub fn now(&self) -> Duration {
        self.lock().now
    }

    pub fn polls(&self) -> u64 {
        self.lock().polls
    }

    pub fn live_tasks(&self, node: NodeId) -> Vec<&'static str> {
        self.lock()
            .tasks
            .values()
            .filter(|s| s.node == node)
            .map(|s| s.name)
            .collect()
    }

    pub fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        let deadline = self.now() + d;
        Box::pin(Sleep {
            handle: self.clone(),
            deadline,
            key: None,
        })
    }

    fn register_timer(
        &self,
        deadline: Duration,
        old: Option<(Duration, u64)>,
        waker: &Waker,
    ) -> (Duration, u64) {
        let mut g = self.lock();
        if let Some(k) = old {
            g.timers.remove(&k);
        }
        let key = (deadline, g.next_timer);
        g.next_timer += 1;
        g.timers.insert(key, waker.clone());
        key
    }

    fn cancel_timer(&self, key: (Duration, u64)) {
        self.lock().timers.remove(&key);
    }
}

struct TaskWaker {
    id: u64,
    handle: Handle,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.handle.lock().enqueue(self.id);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.handle.lock().enqueue(self.id);
    }
}

struct Sleep {
    handle: Handle,
    deadline: Duration,
    key: Option<(Duration, u64)>,
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.handle.now() >= self.deadline {
            if let Some(k) = self.key.take() {
                self.handle.cancel_timer(k);
            }
            return Poll::Ready(());
        }
        let key = self
            .handle
            .register_timer(self.deadline, self.key, cx.waker());
        self.key = Some(key);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.handle.cancel_timer(k);
        }
    }
}
