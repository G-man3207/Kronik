//! A byte budget shared by the writers of one space: a preview's blob space
//! holds at most `[fork] preview_blob_bytes`, because anyone with the
//! preview's URL can upload into it and the collector never sweeps a fork's
//! space (it goes with the fork).
//!
//! Writers charge the plaintext bytes they accept and give them back when
//! they name no new object: aborted, dropped unfinished, or claiming an
//! object of the same identity that is there already. The first charge
//! seeds the budget with the bytes of the objects already in the space, so
//! a daemon restart does not reset it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{BlobError, BlobStore, Space};

/// What the writers of one space may still add.
pub struct SpaceBudget {
    limit: u64,
    used: AtomicU64,
    seeded: tokio::sync::OnceCell<()>,
}

impl SpaceBudget {
    /// A budget of `limit` bytes, seeded from the space at its first charge.
    pub fn new(limit: u64) -> Arc<SpaceBudget> {
        Arc::new(SpaceBudget {
            limit,
            used: AtomicU64::new(0),
            seeded: tokio::sync::OnceCell::new(),
        })
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes counted so far: the space's objects when it was seeded, and
    /// what writers added since.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    /// Bytes that may still be added.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used())
    }

    /// Counts the objects of `space` once (a later call does nothing).
    pub async fn seed(&self, store: &BlobStore, space: &Space) -> Result<(), BlobError> {
        self.seeded
            .get_or_try_init(|| async {
                let bytes = store.space_bytes(space).await?;
                self.used.fetch_add(bytes, Ordering::AcqRel);
                Ok::<(), BlobError>(())
            })
            .await
            .map(|_| ())
    }

    /// Takes `n` bytes, or answers [`BlobError::SpaceFull`] and takes none.
    pub(crate) fn charge(&self, n: u64) -> Result<(), BlobError> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.saturating_add(n);
            if next > self.limit {
                return Err(BlobError::SpaceFull { limit: self.limit });
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(now) => used = now,
            }
        }
    }

    /// Gives back `n` bytes a writer took and named no new object with.
    pub(crate) fn refund(&self, n: u64) {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            match self.used.compare_exchange_weak(
                used,
                used.saturating_sub(n),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(now) => used = now,
            }
        }
    }
}
