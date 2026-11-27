//! Rate limits per grant and target (docs/design/m2-effects.md §6): paced
//! sends, so no window of the period ever holds more than N sends. Callers
//! wait; logical time is unaffected.
//!
//! The windows are not persisted. Instead every window starts full, as if N
//! sends had happened when the process started: the first send waits until
//! one period after startup, so a window spanning a crash and restart never
//! holds more than N sends either.
//!
//! A grant that changes a key's rate is not a restart: that key's window
//! starts over at the new rate's pace, so the new record applies to the next
//! call. The superseded grant's floor is not spent (it could be an hour at
//! `1/h`), and lowering a rate still waits the new pace before the first send.
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

use kronik_core::env::Clock;
use kronik_core::sync::lock;

use crate::config::Rate;

/// The quantization slack on the sliding bound. Clock fuzz (simulator time
/// quanta, scheduler jitter) is milliseconds-scale everywhere the daemon
/// runs; a margin larger than the fuzz decides the period edge safely.
const SLACK: Duration = Duration::from_millis(20);

pub struct RateLimiter {
    /// `Clock::monotonic` at process start.
    started: Duration,
    /// Per key: the pacing state of the rate last seen for it.
    windows: Mutex<BTreeMap<String, Window>>,
}

/// One key's pacing state, rebuilt when a grant changes that key's rate.
struct Window {
    /// The rate this window was built under.
    rate: Rate,
    /// The last `rate.count` send times (the sliding bound).
    sends: VecDeque<Duration>,
    /// The earliest instant the next send may go out (the pacing floor).
    floor: Duration,
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
    pub async fn acquire(&self, clock: &dyn Clock, key: &str, rate: Rate) {
        let count = rate.count.max(1);
        let pace = rate.per / count;
        loop {
            let now = clock.monotonic();
            let wait = {
                let mut g = lock(&self.windows);
                let started = self.started;
                let window = g.entry(key.to_owned()).or_insert_with(|| Window {
                    rate,
                    sends: VecDeque::new(),
                    floor: started + rate.per,
                });
                if window.rate != rate {
                    // The new grant's window starts here, empty and with its
                    // own first pace; the old floor and history do not carry.
                    *window = Window {
                        rate,
                        sends: VecDeque::new(),
                        floor: now + pace,
                    };
                }
                // The sliding bound: the last sends must be older than the
                // period plus the quantization slack.
                while window
                    .sends
                    .front()
                    .is_some_and(|t| now.saturating_sub(*t) >= rate.per + SLACK)
                {
                    window.sends.pop_front();
                }
                let pacing = window.floor.saturating_sub(now);
                let bound = if window.sends.len() >= count as usize {
                    window.sends.front().map_or(Duration::ZERO, |oldest| {
                        oldest.saturating_add(rate.per + SLACK).saturating_sub(now)
                    })
                } else {
                    Duration::ZERO
                };
                let wait = pacing.max(bound);
                if wait.is_zero() {
                    window.sends.push_back(now);
                    window.floor = now + pace;
                    return;
                }
                wait
            };
            clock.sleep(wait.max(Duration::from_millis(1))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use kronik_core::env::{BoxFuture, Clock};

    use super::*;

    /// `sleep` moves this clock forward at once: a test measures the waits
    /// the limiter computes, not the wall time it spends on them.
    struct TestClock(AtomicU64);

    impl TestClock {
        fn new() -> TestClock {
            TestClock(AtomicU64::new(0))
        }
    }

    impl Clock for TestClock {
        fn wall_ms(&self) -> u64 {
            0
        }

        fn monotonic(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }

        fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
            self.0.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
            Box::pin(std::future::ready(()))
        }
    }

    fn rate(s: &str) -> Rate {
        Rate::parse(s).unwrap()
    }

    /// A re-grant takes effect on the key's next call: raising the rate waits
    /// the new pace, not the superseded grant's floor, and lowering it starts
    /// the new window full.
    #[tokio::test]
    async fn a_changed_rate_starts_its_window_over() {
        let clock = TestClock::new();
        let limiter = RateLimiter::starting_full(Duration::ZERO);
        let key = "counter|http:127.0.0.1|127.0.0.1";

        limiter.acquire(&clock, key, rate("1/s")).await;
        assert_eq!(clock.monotonic(), Duration::from_secs(1));
        limiter.acquire(&clock, key, rate("1/s")).await;
        // The full window's sliding bound also takes the quantization slack.
        assert_eq!(clock.monotonic(), Duration::from_millis(2_020));

        // The next send is the first under the raised rate: it waits the new
        // pace, not the second the superseded 1/s floor still owed.
        let before = clock.monotonic();
        limiter.acquire(&clock, key, rate("60/s")).await;
        assert_eq!(clock.monotonic() - before, Duration::from_secs(1) / 60);
        // An unchanged rate keeps the window: the next send is paced too.
        let before = clock.monotonic();
        limiter.acquire(&clock, key, rate("60/s")).await;
        assert_eq!(clock.monotonic() - before, Duration::from_secs(1) / 60);

        // A lowered rate cannot send at the old pace: its first call waits a
        // full new pace.
        let before = clock.monotonic();
        limiter.acquire(&clock, key, rate("1/s")).await;
        assert_eq!(clock.monotonic() - before, Duration::from_secs(1));
    }
}
