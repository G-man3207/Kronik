//! Pending timers by due time (docs/design/m2-effects.md §7). The rows live
//! in `state.db`; the wheel only orders them and remembers which are firing.
//!
//! A timer is due at a logical time (ADR 0006). It fires when logical time
//! (`max(wall clock, high-water mark)`) reaches that time, or when the delay
//! that was left when the wheel took it has passed on the monotonic clock,
//! whichever comes first. A host clock that steps back holds logical time
//! still for the length of the step, but delays no timer (#40); one that
//! steps forward fires the timers logical time passes.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use kronik_core::ids::ActorRef;

/// The present on both clocks the wheel reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Now {
    /// `max(wall clock, high-water mark)`: the logical time a turn starting
    /// now gets, but for its parent.
    pub logical_ms: u64,
    /// `Clock::monotonic`.
    pub monotonic: Duration,
}

#[derive(Default)]
pub(crate) struct Wheel {
    due: BTreeSet<(u64, ActorRef, u64)>,
    deadlines: BTreeSet<(Duration, ActorRef, u64)>,
    /// Each timer's due time and monotonic deadline.
    by_id: BTreeMap<(ActorRef, u64), (u64, Duration)>,
    firing: BTreeSet<(ActorRef, u64)>,
}

impl Wheel {
    /// Adds a timer due at logical time `due`. Its monotonic deadline is
    /// `now` plus the delay left: `due` less the logical time now.
    pub fn add(&mut self, actor: ActorRef, id: u64, due: u64, now: Now) {
        self.remove(&actor, id);
        let left = Duration::from_millis(due.saturating_sub(now.logical_ms));
        let deadline = now.monotonic.saturating_add(left);
        self.due.insert((due, actor.clone(), id));
        self.deadlines.insert((deadline, actor.clone(), id));
        self.by_id.insert((actor, id), (due, deadline));
    }

    pub fn remove(&mut self, actor: &ActorRef, id: u64) {
        if let Some((due, deadline)) = self.by_id.remove(&(actor.clone(), id)) {
            self.due.remove(&(due, actor.clone(), id));
            self.deadlines.remove(&(deadline, actor.clone(), id));
        }
    }

    /// How long from `now` until the next timer is due, by either clock.
    pub fn next_wait(&self, now: Now) -> Option<Duration> {
        let logical = self
            .due
            .first()
            .map(|(due, _, _)| Duration::from_millis(due.saturating_sub(now.logical_ms)));
        let monotonic = self
            .deadlines
            .first()
            .map(|(deadline, _, _)| deadline.saturating_sub(now.monotonic));
        logical.into_iter().chain(monotonic).min()
    }

    /// Timers due at `now` by either clock, in order of due time, moved to
    /// the firing set.
    pub fn take_due(&mut self, now: Now) -> Vec<(ActorRef, u64, u64)> {
        let mut ready: BTreeSet<(u64, ActorRef, u64)> = self
            .due
            .iter()
            .take_while(|(due, _, _)| *due <= now.logical_ms)
            .cloned()
            .collect();
        for (_, actor, id) in self
            .deadlines
            .iter()
            .take_while(|(deadline, _, _)| *deadline <= now.monotonic)
        {
            if let Some((due, _)) = self.by_id.get(&(actor.clone(), *id)) {
                ready.insert((*due, actor.clone(), *id));
            }
        }
        let mut out = Vec::new();
        for (due, actor, id) in ready {
            self.remove(&actor, id);
            if self.firing.insert((actor.clone(), id)) {
                out.push((actor, id, due));
            }
        }
        out
    }

    /// The timer's turn finished (or was skipped).
    pub fn done(&mut self, actor: &ActorRef, id: u64) {
        self.firing.remove(&(actor.clone(), id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(logical_ms: u64, monotonic_ms: u64) -> Now {
        Now {
            logical_ms,
            monotonic: Duration::from_millis(monotonic_ms),
        }
    }

    #[test]
    fn orders_by_due_time() {
        let a = ActorRef::parse("t/a").unwrap();
        let mut w = Wheel::default();
        let now = at(0, 0);
        w.add(a.clone(), 1, 30, now);
        w.add(a.clone(), 2, 10, now);
        w.add(a.clone(), 3, 20, now);
        w.remove(&a, 3);
        assert_eq!(w.next_wait(now), Some(Duration::from_millis(10)));
        assert_eq!(w.take_due(at(25, 25)), vec![(a.clone(), 2, 10)]);
        assert_eq!(w.next_wait(at(25, 25)), Some(Duration::from_millis(5)));
        w.done(&a, 2);
        assert!(w.take_due(at(29, 29)).is_empty());
    }

    /// #40: after the host clock steps back, logical time holds still at
    /// the high-water mark, but timers fire after the delay they had left,
    /// counted on the monotonic clock: those added before the step and
    /// those added during it.
    #[test]
    fn a_clock_step_back_delays_no_timer() {
        let a = ActorRef::parse("t/a").unwrap();
        let mut w = Wheel::default();
        // At logical 100 000, a timer due in 1 s.
        w.add(a.clone(), 1, 101_000, at(100_000, 0));
        // The wall clock steps back 5 minutes: logical time holds still at
        // the high-water mark (100 000) while the monotonic clock goes on.
        w.add(a.clone(), 2, 101_000, at(100_000, 200));
        assert_eq!(
            w.next_wait(at(100_000, 500)),
            Some(Duration::from_millis(500))
        );
        assert!(w.take_due(at(100_000, 999)).is_empty());
        assert_eq!(
            w.take_due(at(100_000, 1_000)),
            vec![(a.clone(), 1, 101_000)]
        );
        assert_eq!(
            w.next_wait(at(100_000, 1_000)),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            w.take_due(at(100_000, 1_200)),
            vec![(a.clone(), 2, 101_000)]
        );
        // A step forward fires what logical time passes, at once.
        w.add(a.clone(), 3, 200_000, at(100_000, 2_000));
        assert_eq!(
            w.take_due(at(200_000, 2_001)),
            vec![(a.clone(), 3, 200_000)]
        );
        assert_eq!(w.next_wait(at(200_000, 2_001)), None);
    }

    /// Timers due by either clock come out in order of due time, once.
    #[test]
    fn both_clocks_give_one_ordered_batch() {
        let a = ActorRef::parse("t/a").unwrap();
        let b = ActorRef::parse("t/b").unwrap();
        let mut w = Wheel::default();
        // Due at 50, deadline 50 ms: at (55, 40) due by logical time only.
        w.add(a.clone(), 1, 50, at(0, 0));
        // Due at 60, deadline 30 ms: at (55, 40) due by its deadline only.
        w.add(b.clone(), 2, 60, at(30, 0));
        assert_eq!(
            w.take_due(at(55, 40)),
            vec![(a.clone(), 1, 50), (b.clone(), 2, 60)]
        );
        assert!(w.take_due(at(1_000, 10_000)).is_empty());
    }
}
