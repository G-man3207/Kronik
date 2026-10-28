//! Rate limits per grant and target (docs/design/m2-effects.md §6): a
//! sliding window of the last N send times, so no window of the period ever
//! holds more than N sends. Callers wait; logical time is unaffected.
//!
//! The windows are not persisted. Instead every window starts full, as if N
//! sends had happened when the process started: the first send waits until
//! one period after startup, so a window spanning a crash and restart never
//! holds more than N sends either.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use kronik_core::env::Env;

use crate::config::Rate;

pub struct RateLimiter {
    /// `Clock::monotonic` at process start.
    started: Duration,
    windows: Mutex<BTreeMap<String, VecDeque<Duration>>>,
}

impl RateLimiter {
    /// A limiter whose windows start full at `started` (the process start,
    /// on `Env::clock`'s monotonic clock).
    pub fn starting_full(started: Duration) -> RateLimiter {
        RateLimiter {
            started,
            windows: Mutex::new(BTreeMap::new()),
        }
    }

    /// Waits until a call under `rate` is allowed for `key` (grant and
    /// target), then counts it.
    pub async fn acquire(&self, env: &Env, key: &str, rate: Rate) {
        loop {
            let wait = {
                let now = env.clock.monotonic();
                let mut g = self.windows.lock().unwrap_or_else(|e| e.into_inner());
                let started = self.started;
                let w = g
                    .entry(key.to_owned())
                    .or_insert_with(|| std::iter::repeat_n(started, rate.count as usize).collect());
                while w
                    .front()
                    .is_some_and(|t| now.saturating_sub(*t) >= rate.per)
                {
                    w.pop_front();
                }
                if w.len() < rate.count as usize {
                    w.push_back(now);
                    return;
                }
                match w.front() {
                    Some(oldest) => (*oldest + rate.per).saturating_sub(now),
                    None => Duration::ZERO,
                }
            };
            env.clock.sleep(wait.max(Duration::from_millis(1))).await;
        }
    }
}
