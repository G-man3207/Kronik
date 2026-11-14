//! The pace of a body read as it arrives (`[gateway] upload_min_rate`): an
//! upload that becomes a blob has no whole-body timeout (M25 §6.2), only the
//! idle timeout between chunks. A client sending a byte just inside that
//! timeout would otherwise hold its connection, its writer and its part file
//! indefinitely. So once `grace` has passed, the bytes that arrived in the
//! last `window` must average `rate` per second.
//!
//! The check runs when a chunk arrives; the idle timeout bounds the silence
//! in between. A source is never cut on a timer of its own, since a body
//! source need not be safe to cancel mid-read.

use std::collections::VecDeque;
use std::time::Duration;

/// One body's pace.
pub(crate) struct Pace {
    /// Bytes per second; 0: no check.
    rate: u64,
    window: Duration,
    grace: Duration,
    start: Duration,
    total: u64,
    /// `(time, bytes received by then)`, oldest first: the newest sample at
    /// or before the window's start, then the window's. Close samples are
    /// merged, so there are at most about 32 per window.
    samples: VecDeque<(Duration, u64)>,
}

/// A body too slow: what the last window brought, over how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TooSlow {
    pub bytes: u64,
    pub span: Duration,
}

impl Pace {
    /// A body whose reading starts at `now` (monotonic).
    pub(crate) fn new(rate: u64, window: Duration, grace: Duration, now: Duration) -> Pace {
        let mut samples = VecDeque::new();
        samples.push_back((now, 0));
        Pace {
            rate,
            window,
            grace,
            start: now,
            total: 0,
            samples,
        }
    }

    /// Counts `bytes` that arrived at `now`. Past the grace, too few bytes
    /// in the last window is [`TooSlow`].
    pub(crate) fn arrived(&mut self, now: Duration, bytes: u64) -> Result<(), TooSlow> {
        self.total = self.total.saturating_add(bytes);
        if self.rate == 0 || self.window.is_zero() {
            return Ok(());
        }
        let step = (self.window / 32).max(Duration::from_millis(100));
        let merge = self.samples.len() > 1
            && self
                .samples
                .back()
                .is_some_and(|last| now.saturating_sub(last.0) < step);
        match self.samples.back_mut() {
            // Close to the previous sample (not the start's): merged.
            Some(last) if merge => *last = (now, self.total),
            _ => self.samples.push_back((now, self.total)),
        }
        let from = now.saturating_sub(self.window);
        while self.samples.len() >= 2 && self.samples[1].0 <= from {
            self.samples.pop_front();
        }
        let elapsed = now.saturating_sub(self.start);
        if elapsed < self.grace {
            return Ok(());
        }
        // What arrived after the newest sample at or before the window's
        // start (the start's own, with 0 bytes, while the window reaches
        // back before it).
        let base = match self.samples.front() {
            Some((at, received)) if *at <= from => *received,
            _ => 0,
        };
        let span = self.window.min(elapsed);
        let got = self.total.saturating_sub(base);
        let need =
            u64::try_from(u128::from(self.rate) * span.as_millis() / 1000).unwrap_or(u64::MAX);
        if got < need {
            return Err(TooSlow { bytes: got, span });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    /// A byte just inside the idle timeout, every 29 s, fails once the grace
    /// has passed; a steady body above the rate never does.
    #[test]
    fn a_trickle_fails_after_the_grace_and_a_steady_body_passes() {
        let mut slow = Pace::new(8192, s(30), s(30), s(0));
        assert_eq!(slow.arrived(s(29), 1), Ok(()));
        // Both bytes are within the last 30 s.
        assert_eq!(
            slow.arrived(s(58), 1),
            Err(TooSlow {
                bytes: 2,
                span: s(30)
            })
        );

        let mut steady = Pace::new(8192, s(30), s(30), s(0));
        for t in 1..=600 {
            assert_eq!(steady.arrived(s(t), 10_000), Ok(()), "at {t} s");
        }
        assert!(steady.samples.len() <= 40, "{}", steady.samples.len());
    }

    /// Fast at first, then a trickle: the window forgets the early bytes.
    #[test]
    fn early_bytes_do_not_pay_for_a_later_trickle() {
        let mut pace = Pace::new(8192, s(30), s(30), s(0));
        assert_eq!(pace.arrived(s(1), 100 << 20), Ok(()));
        assert_eq!(pace.arrived(s(29), 1), Ok(()));
        assert_eq!(
            pace.arrived(s(58), 1),
            Err(TooSlow {
                bytes: 2,
                span: s(30)
            })
        );
    }

    /// A rate of 0 turns the check off; within the grace nothing is checked.
    #[test]
    fn no_rate_or_within_the_grace_is_never_too_slow() {
        let mut off = Pace::new(0, s(30), s(30), s(0));
        assert_eq!(off.arrived(s(1000), 1), Ok(()));
        let mut early = Pace::new(8192, s(30), s(60), s(0));
        assert_eq!(early.arrived(s(59), 1), Ok(()));
        assert!(early.arrived(s(61), 1).is_err());
    }
}
