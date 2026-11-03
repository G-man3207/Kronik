//! Rate limits per grant and target (docs/design/m2-effects.md §6): paced
//! sends, so no window of the period ever holds more than N sends. Callers
//! wait; logical time is unaffected.
//!
//! The windows are not persisted. Instead every window starts full, as if N
//! sends had happened when the process started: the first send waits until
//! one period after startup, so a window spanning a crash and restart never
//! holds more than N sends either.
//!
//! Two mechanisms hold the line on any clock accounting:
//! - Pacing: admitted sends space at least one `period / count` apart, so
//!   the daemon never bursts N at a window boundary (a boundary burst can
//!   straddle the receiver's clock and read as N+ε in one observed window).
//! - A safety margin on the sliding bound: the Nth prior send must be at
//!   least the period plus a small slack in the past, so clock-quantization
//!   fuzz at the exact period edge can never count a boundary send as
//!   inside. A restart re-seeds full (the first send still waits one full
//!   period), so a restart can never increase the send rate.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use kronik_core::env::Env;

use crate::config::Rate;

/// The quantization slack on the sliding bound. Clock fuzz (simulator time
/// quanta, scheduler jitter) is milliseconds-scale everywhere the daemon
/// runs; a margin larger than the fuzz decides the period edge safely.
const SLACK: Duration = Duration::from_millis(20);

pub struct RateLimiter {
    /// `Clock::monotonic` at process start.
    started: Duration,
    /// Per key: the last `count` send times (the sliding bound) and the
    /// earliest instant the next send may go out (the pacing floor).
    windows: Mutex<BTreeMap<String, (VecDeque<Duration>, Duration)>>,
}

impl RateLimiter {
    /// A limiter whose windows start full at `started` (the process start,
    /// on `Env::clock`'s monotonic clock): the first send waits one period.
    pub fn starting_full(started: Duration) -> RateLimiter {
        RateLimiter {
            started,
            windows: Mutex::new(BTreeMap::new()),
        }
    }

    /// Waits until a call under `rate` is allowed for `key` (grant and
    /// target), then counts it.
    pub async fn acquire(&self, env: &Env, key: &str, rate: Rate) {
        let pace = rate.per / rate.count.max(1);
        loop {
            let now = env.clock.monotonic();
            let wait = {
                let mut g = self.windows.lock().unwrap_or_else(|e| e.into_inner());
                let started = self.started;
                let count = rate.count.max(1) as usize;
                let (window, floor) = g
                    .entry(key.to_owned())
                    .or_insert_with(|| (VecDeque::new(), started + rate.per));
                // The sliding bound: the last sends must be older than the
                // period plus the quantization slack.
                while window
                    .front()
                    .is_some_and(|t| now.saturating_sub(*t) >= rate.per + SLACK)
                {
                    window.pop_front();
                }
                let pacing = floor.saturating_sub(now);
                let bound = if window.len() >= count {
                    window.front().map_or(Duration::ZERO, |oldest| {
                        oldest.saturating_add(rate.per + SLACK).saturating_sub(now)
                    })
                } else {
                    Duration::ZERO
                };
                let wait = pacing.max(bound);
                if wait.is_zero() {
                    window.push_back(now);
                    *floor = now + pace;
                    return;
                }
                wait
            };
            env.clock.sleep(wait.max(Duration::from_millis(1))).await;
        }
    }
}
