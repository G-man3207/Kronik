//! Pending timers by due time (docs/design/m2-effects.md §7). The rows live
//! in `state.db`; the wheel only orders them and remembers which are firing.

use std::collections::{BTreeMap, BTreeSet};

use kronik_core::ids::ActorRef;

#[derive(Default)]
pub(crate) struct Wheel {
    due: BTreeSet<(u64, ActorRef, u64)>,
    by_id: BTreeMap<(ActorRef, u64), u64>,
    firing: BTreeSet<(ActorRef, u64)>,
}

impl Wheel {
    pub fn add(&mut self, actor: ActorRef, id: u64, due: u64) {
        self.remove(&actor, id);
        self.due.insert((due, actor.clone(), id));
        self.by_id.insert((actor, id), due);
    }

    pub fn remove(&mut self, actor: &ActorRef, id: u64) {
        if let Some(due) = self.by_id.remove(&(actor.clone(), id)) {
            self.due.remove(&(due, actor.clone(), id));
        }
    }

    pub fn next_due(&self) -> Option<u64> {
        self.due.iter().next().map(|(d, _, _)| *d)
    }

    /// Timers due at `now`, moved to the firing set.
    pub fn take_due(&mut self, now: u64) -> Vec<(ActorRef, u64, u64)> {
        let mut out = Vec::new();
        while let Some((due, actor, id)) = self.due.iter().next().cloned() {
            if due > now {
                break;
            }
            self.due.remove(&(due, actor.clone(), id));
            self.by_id.remove(&(actor.clone(), id));
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

    #[test]
    fn orders_by_due_time() {
        let a = ActorRef::parse("t/a").unwrap();
        let mut w = Wheel::default();
        w.add(a.clone(), 1, 30);
        w.add(a.clone(), 2, 10);
        w.add(a.clone(), 3, 20);
        w.remove(&a, 3);
        assert_eq!(w.next_due(), Some(10));
        assert_eq!(w.take_due(25), vec![(a.clone(), 2, 10)]);
        assert_eq!(w.next_due(), Some(30));
        w.done(&a, 2);
        assert!(w.take_due(29).is_empty());
    }
}
