//! Leases (ADR 0120 §4): in-memory roots with an expiry that their holder
//! renews while it runs. A crash ends every lease with the process; a holder
//! that stops renewing loses its lease at expiry, so a stuck replay does not
//! hold blobs forever.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Clock;
use kronik_core::sync::lock;

use crate::BlobId;

struct Entry {
    holder: &'static str,
    /// On the monotonic clock.
    expires: Duration,
    ids: BTreeSet<BlobId>,
    /// A floor lease: records at or after this LSN stay roots.
    floor: Option<u64>,
}

#[derive(Default)]
struct Table {
    next: u64,
    entries: BTreeMap<u64, Entry>,
}

/// Every lease of a store.
pub struct Leases {
    clock: Arc<dyn Clock>,
    ttl: Duration,
    table: Mutex<Table>,
}

impl Leases {
    pub fn new(clock: Arc<dyn Clock>, ttl: Duration) -> Arc<Leases> {
        Arc::new(Leases {
            clock,
            ttl,
            table: Mutex::new(Table::default()),
        })
    }

    fn insert(self: &Arc<Self>, holder: &'static str, floor: Option<u64>) -> Lease {
        let expires = self.clock.monotonic() + self.ttl;
        let mut t = lock(&self.table);
        t.next += 1;
        let id = t.next;
        t.entries.insert(
            id,
            Entry {
                holder,
                expires,
                ids: BTreeSet::new(),
                floor,
            },
        );
        Lease(Arc::new(Handle {
            leases: self.clone(),
            id,
        }))
    }

    /// A lease on a set of blobs, empty until [`Lease::add`].
    pub fn take(self: &Arc<Self>, holder: &'static str) -> Lease {
        self.insert(holder, None)
    }

    /// A lease that keeps every record from `lsn` on a root (a replay or
    /// proposal at its fork point), and blobs it adds.
    pub fn floor(self: &Arc<Self>, holder: &'static str, lsn: u64) -> Lease {
        self.insert(holder, Some(lsn))
    }

    fn live<'a>(&self, t: &'a Table) -> impl Iterator<Item = &'a Entry> {
        let now = self.clock.monotonic();
        t.entries.values().filter(move |e| e.expires > now)
    }

    /// Whether an unexpired lease holds `id`.
    pub fn is_leased(&self, id: &BlobId) -> bool {
        let t = lock(&self.table);
        self.live(&t).any(|e| e.ids.contains(id))
    }

    /// Every blob an unexpired lease holds.
    pub fn leased(&self) -> BTreeSet<BlobId> {
        let t = lock(&self.table);
        self.live(&t).flat_map(|e| e.ids.iter().copied()).collect()
    }

    /// The lowest floor of the unexpired floor leases.
    pub fn lowest_floor(&self) -> Option<u64> {
        let t = lock(&self.table);
        self.live(&t).filter_map(|e| e.floor).min()
    }

    /// The holders of the unexpired leases, for `kronik_blob_leases` and
    /// `kronik blobs inspect`.
    pub fn holders(&self) -> Vec<&'static str> {
        let t = lock(&self.table);
        self.live(&t).map(|e| e.holder).collect()
    }
}

struct Handle {
    leases: Arc<Leases>,
    id: u64,
}

impl Drop for Handle {
    fn drop(&mut self) {
        lock(&self.leases.table).entries.remove(&self.id);
    }
}

/// One lease. Clones share it; it ends when the last clone is dropped, or
/// when it was not renewed for the store's lease TTL.
#[derive(Clone)]
pub struct Lease(Arc<Handle>);

impl Lease {
    /// Adds a blob to the lease.
    pub fn add(&self, id: BlobId) {
        if let Some(e) = lock(&self.0.leases.table).entries.get_mut(&self.0.id) {
            e.ids.insert(id);
        }
    }

    /// Renews the lease every quarter of its TTL (at most every 30 s)
    /// while any clone of it exists, so that a lease held longer than the
    /// TTL (a slow upload, a long streamed answer, a replay) stays in force
    /// until it is dropped (ADR 0120 §4).
    pub fn keep_alive(&self, env: &kronik_core::env::Env) {
        let weak = Arc::downgrade(&self.0);
        let every = (self.0.leases.ttl / 4).clamp(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_secs(30),
        );
        let clock = env.clock.clone();
        drop(env.spawn("blob lease renewal", async move {
            loop {
                clock.sleep(every).await;
                match weak.upgrade() {
                    Some(handle) => Lease(handle).renew(),
                    None => return,
                }
            }
        }));
    }

    /// Extends the lease by the TTL from now.
    pub fn renew(&self) {
        let expires = self.0.leases.clock.monotonic() + self.0.leases.ttl;
        if let Some(e) = lock(&self.0.leases.table).entries.get_mut(&self.0.id) {
            e.expires = expires;
        }
    }

    /// Whether the lease is still in force (not expired).
    pub fn is_live(&self) -> bool {
        let now = self.0.leases.clock.monotonic();
        lock(&self.0.leases.table)
            .entries
            .get(&self.0.id)
            .is_some_and(|e| e.expires > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn wall_ms(&self) -> u64 {
            0
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
        fn sleep(&self, _d: Duration) -> kronik_core::env::BoxFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    #[test]
    fn leases_hold_until_dropped_or_expired() {
        let clock = Arc::new(TestClock(AtomicU64::new(0)));
        let leases = Leases::new(clock.clone(), Duration::from_secs(300));
        let a = BlobId::plain([1; 32]);
        let b = BlobId::plain([2; 32]);
        let turn = leases.take("turn");
        turn.add(a);
        let shared = turn.clone();
        shared.add(b);
        assert!(leases.is_leased(&a) && leases.is_leased(&b));
        assert_eq!(leases.leased().len(), 2);
        drop(turn);
        // A clone keeps the lease.
        assert!(leases.is_leased(&a));
        drop(shared);
        assert!(!leases.is_leased(&a));

        let replay = leases.floor("replay", 40);
        let other = leases.floor("proposal", 12);
        assert_eq!(leases.lowest_floor(), Some(12));
        // Not renewed for longer than the TTL: no longer a root.
        clock.0.store(301, Ordering::Relaxed);
        replay.renew();
        assert!(replay.is_live() && !other.is_live());
        assert_eq!(leases.lowest_floor(), Some(40));
        assert_eq!(leases.holders(), ["replay"]);
    }
}
