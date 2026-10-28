//! The transport to foreign actors (docs/design/m7-foreign.md §5, §7): the
//! daemon's effect gate sends `foreign://<name>/...` calls through a
//! [`ForeignHost`], and the node asks it to bring the sandboxes in line
//! with the declared foreign actors. `kronik-foreign` implements it; DST,
//! forks and the test host have none, so foreign calls there are never live
//! (I7).

use std::path::PathBuf;
use std::sync::Arc;

use kronik_core::env::{BoxFuture, HttpRequest, HttpResponse, NetError};
use kronik_privacy::SecretStore;
use kronik_proto::log::v1 as pb;

pub trait ForeignHost: Send + Sync + 'static {
    /// Starts every declared actor that is not running and stops every
    /// running actor that is no longer declared (I5: the declarations are
    /// the `ForeignActor` records of the current epoch). Resolves once each
    /// newly started actor is running or has failed its first start, so the
    /// node can call it before re-running open turns.
    fn reconcile(
        &self,
        declared: Vec<pb::ForeignActor>,
        secrets: Option<Arc<SecretStore>>,
    ) -> BoxFuture<'static, ()>;

    /// Sends one request to `req.url` (`foreign://<name>/...`). Errors follow
    /// [`NetError`]: `Connect` when the request never reached the sandbox
    /// (the message starts with `FOREIGN_UNAVAILABLE:`), `Io` when the
    /// outcome is unknown, `TooLarge` past `max_response_bytes`.
    fn http(
        &self,
        name: &str,
        req: HttpRequest,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>>;

    /// Checkpoints the running actor `name` at main's LSN `lsn` (M14, ADR
    /// 0019). `hold` keeps main's turns drained: the host drops it as soon
    /// as main's calls to `name` wait in the daemon, so main is not held
    /// for the copy of the data directory and the runsc steps. `budget`:
    /// the bytes free above `[log] disk_reserve` (None: no reserve); a
    /// checkpoint whose data would not fit is refused.
    fn checkpoint(
        &self,
        name: &str,
        lsn: u64,
        hold: Box<dyn std::any::Any + Send>,
        budget: Option<u64>,
    ) -> BoxFuture<'static, Result<Checkpoint, String>> {
        let _ = budget;
        drop(hold);
        let name = name.to_owned();
        Box::pin(async move { Err(format!("{name}: this host takes no checkpoints ({lsn})")) })
    }

    /// The checkpoints of `name`, oldest first.
    fn checkpoints(&self, _name: &str) -> Vec<Checkpoint> {
        Vec::new()
    }

    /// Starts a fork's copy of an actor from a checkpoint (M14).
    fn start_copy(
        &self,
        spec: CopySpec,
    ) -> BoxFuture<'static, Result<Arc<dyn ForeignCopy>, String>> {
        Box::pin(async move { Err(format!("{}: this host runs no copies", spec.name)) })
    }
}

/// One checkpoint of a foreign actor: the sandbox's memory, its data
/// directory and its runtime spec at main's LSN `lsn` (M14, ADR 0019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub name: String,
    pub lsn: u64,
    pub dir: PathBuf,
    pub at_ms: u64,
    pub bytes: u64,
}

/// A fork's copy to start: the actor, the checkpoint, and the directory the
/// copy's disk lives in (deleted with the copy).
#[derive(Debug, Clone)]
pub struct CopySpec {
    pub fork: String,
    pub name: String,
    pub checkpoint: Checkpoint,
    pub dir: PathBuf,
}

/// A running copy of a foreign actor in a fork: no network out, its own
/// disk (M14).
pub trait ForeignCopy: Send + Sync + 'static {
    /// As [`ForeignHost::http`], to the copy.
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>>;
    /// Stops the copy and deletes its disk.
    fn stop(&self) -> BoxFuture<'static, ()>;
}

/// The error text of a call that cannot reach a foreign actor.
pub fn unavailable(name: &str, why: &str) -> NetError {
    NetError::Connect(format!("FOREIGN_UNAVAILABLE: {name}: {why}"))
}

/// An optional [`ForeignHost`] for settings that are `Debug + Clone` (the
/// scheduler's `NodeConfig`). `None`: foreign calls are never live.
#[derive(Clone, Default)]
pub struct ForeignSlot(pub Option<Arc<dyn ForeignHost>>);

impl std::fmt::Debug for ForeignSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "ForeignSlot(host)"
        } else {
            "ForeignSlot(none)"
        })
    }
}

/// A foreign actor's name: DNS-style labels `[a-z0-9]([a-z0-9-]*[a-z0-9])?`
/// joined by dots, at most 63 characters (`echo`, `payments.internal`).
pub fn valid_name(name: &str) -> bool {
    name.len() <= 63
        && !name.is_empty()
        && name.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn names_are_dns_style() {
        for ok in ["echo", "payments.internal", "a", "a-1.b2", &"x".repeat(63)] {
            assert!(super::valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Echo",
            "-echo",
            "echo-",
            "a..b",
            ".a",
            "a.",
            "a_b",
            "a/b",
            &"x".repeat(64),
        ] {
            assert!(!super::valid_name(bad), "{bad}");
        }
    }
}
