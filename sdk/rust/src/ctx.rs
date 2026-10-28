use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::bindings::kronik::actor::{
    context, crypto, log, messaging, privacy, secrets, state, timers,
};
use crate::types::{from_json, to_json};
use crate::{ActorRef, Error, Http, Level, Message, Secret, Sql};

/// A turn's access to the host: state, SQL, messages, effects, time,
/// randomness and logging.
///
/// The methods are the API that Kronik's SDKs share: `state`, `sql`, `send`,
/// `call`, `http`, `crypto`, `timers`, `now`, `random`, `causal_id`,
/// `secret`, `subject` and `log`.
pub struct Ctx {
    _private: (),
}

impl Ctx {
    pub(crate) fn new() -> Self {
        Ctx { _private: () }
    }

    /// The actor's key-value state (see `kronik explain actor`).
    pub fn state(&self) -> State {
        State { _private: () }
    }

    /// The actor's SQL database (see `kronik explain sql-state`).
    pub fn sql(&self) -> Sql {
        Sql::new()
    }

    /// Sends `message` to the actor `to`. The message is buffered and
    /// delivered exactly once, and only if this turn commits.
    pub fn send(&self, to: &ActorRef, message: &Message) {
        messaging::send(to, message);
    }

    /// Calls the actor `to` with `message` and waits for its reply.
    ///
    /// The callee runs and commits its own turn now; the call is not atomic
    /// with this turn. If this turn fails afterwards, `compensate` (if given)
    /// is delivered to the callee exactly once. Available from M2.
    pub fn call(
        &self,
        to: &ActorRef,
        message: &Message,
        compensate: Option<&Message>,
    ) -> Result<Option<Message>, Error> {
        messaging::call(to, message, compensate).map_err(Error::Call)
    }

    /// Outgoing HTTP requests (see `kronik explain effect`). Available from
    /// M2; in M1 every request is denied.
    pub fn http(&self) -> Http {
        Http::new()
    }

    /// HMAC and signatures computed by the host with a secret (see
    /// `kronik explain secret-handle`). Available from M2.
    pub fn crypto(&self) -> Crypto {
        Crypto { _private: () }
    }

    /// A handle to the secret called `name`. The guest never sees its value;
    /// use it in [`Request::secret_header`](crate::http::Request::secret_header)
    /// or [`Ctx::crypto`].
    pub fn secret(&self, name: impl Into<String>) -> Secret {
        Secret::new(name.into())
    }

    /// The exception path for secrets: revealing a value inside the guest.
    pub fn secrets(&self) -> Secrets {
        Secrets { _private: () }
    }

    /// Timers that deliver a message to this actor later. Available from M2.
    pub fn timers(&self) -> Timers {
        Timers { _private: () }
    }

    /// The turn's logical time in milliseconds since the Unix epoch (see
    /// `kronik explain logical-time`): constant within the turn, never lower
    /// than a previous turn's or the time of the message that started it,
    /// and recorded, so a replay sees the same value.
    pub fn now(&self) -> u64 {
        context::now_ms()
    }

    /// Randomness from the turn's recorded seed: a replay gets the same
    /// bytes.
    pub fn random(&self) -> Random {
        Random { _private: () }
    }

    /// The turn's correlation id (see `kronik explain causal-id`): derived
    /// from the input's causal key, so it is the same in production and in
    /// replay.
    pub fn causal_id(&self) -> String {
        context::causal_id()
    }

    /// This actor, `kind/key`.
    pub fn self_ref(&self) -> ActorRef {
        context::self_ref()
    }

    /// Sets the default subject for values written from now on in this turn,
    /// such as `"user:123"` (see `kronik explain subject`); `None` writes
    /// without a subject. State values get the subject as their tag; SQL
    /// rows get it through `kronik_subject()`.
    pub fn subject<'a>(&self, subject: impl Into<Option<&'a str>>) {
        privacy::set_subject(subject.into());
    }

    /// The current default subject: the one set with [`Ctx::subject`], else
    /// the one the input came with.
    pub fn current_subject(&self) -> Option<String> {
        privacy::current_subject()
    }

    /// The actor's log. The host adds the turn's ids to every event.
    pub fn log(&self) -> Log {
        Log { _private: () }
    }
}

/// The actor's key-value state. Writes are buffered and applied only if the
/// turn commits. Values are at most 1 MiB by default.
pub struct State {
    _private: (),
}

impl State {
    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        state::get(key)
    }

    /// The value of `key` parsed as JSON.
    pub fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Error> {
        state::get(key)
            .map(|v| from_json(&v, &format!("state value {key:?}"), "actor"))
            .transpose()
    }

    /// Sets `key` to `value`, tagged with the turn's default subject.
    pub fn set(&self, key: &str, value: impl AsRef<[u8]>) {
        state::set(key, value.as_ref());
    }

    /// Sets `key` to `value` as JSON, tagged with the turn's default subject.
    pub fn set_json<T: Serialize + ?Sized>(&self, key: &str, value: &T) -> Result<(), Error> {
        state::set(
            key,
            &to_json(value, &format!("state value {key:?}"), "actor")?,
        );
        Ok(())
    }

    /// Sets `key` to `value`, tagged with `subject` (`None`: no subject)
    /// whatever the turn's default subject is.
    pub fn set_for(&self, subject: Option<&str>, key: &str, value: impl AsRef<[u8]>) {
        state::set_for(subject, key, value.as_ref());
    }

    /// Deletes `key`.
    pub fn delete(&self, key: &str) {
        state::delete(key);
    }

    /// The keys that start with `prefix`.
    pub fn keys(&self, prefix: &str) -> Vec<String> {
        state::keys(prefix)
    }
}

/// Randomness from the turn's recorded seed.
pub struct Random {
    _private: (),
}

/// The host traps on larger random requests.
const MAX_RANDOM_REQUEST: usize = 1 << 20;

impl Random {
    /// `len` random bytes, at most 1 MiB (more traps).
    pub fn bytes(&self, len: u32) -> Vec<u8> {
        context::random_bytes(len)
    }

    /// Fills `buf` with random bytes, in requests of at most 1 MiB.
    pub fn fill(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(MAX_RANDOM_REQUEST) {
            // A chunk is at most 1 MiB, so its length fits in u32.
            let bytes = context::random_bytes(chunk.len() as u32);
            chunk.copy_from_slice(&bytes);
        }
    }

    /// A random `u64`.
    pub fn u64(&self) -> u64 {
        let mut b = [0_u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
}

/// Timers: a message to this actor after a delay.
pub struct Timers {
    _private: (),
}

impl Timers {
    /// Schedules `message` to arrive at this actor as a timer input after
    /// `delay` (rounded down to milliseconds). The timer is registered only
    /// if the turn commits. Returns its id.
    pub fn schedule(&self, delay: Duration, message: &Message) -> u64 {
        let ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        timers::schedule(ms, message)
    }

    /// Cancels the timer `id`. Returns whether it was pending.
    pub fn cancel(&self, id: u64) -> bool {
        timers::cancel(id)
    }
}

/// Crypto computed by the host with a secret's value.
pub struct Crypto {
    _private: (),
}

impl Crypto {
    /// HMAC-SHA256 of `data` keyed with `secret`. Needs the capability
    /// `secret:<name>`.
    pub fn hmac_sha256(&self, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::hmac_sha256(secret.name(), data).map_err(Error::Crypto)
    }

    /// An Ed25519 signature of `data` with the private key `secret`. Needs
    /// the capability `secret:<name>`.
    pub fn sign_ed25519(&self, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::sign_ed25519(secret.name(), data).map_err(Error::Crypto)
    }
}

/// Revealing secrets: the exception path.
pub struct Secrets {
    _private: (),
}

impl Secrets {
    /// The value of `secret` inside the guest. Needs its own capability,
    /// `secret-reveal:<name>`; prefer secret headers and [`Ctx::crypto`],
    /// which keep the value out of the guest.
    pub fn reveal(&self, secret: &Secret) -> Result<String, Error> {
        secrets::reveal(secret.name()).map_err(Error::Reveal)
    }
}

/// The actor's log. Events go to the turn's history with the turn's ids.
pub struct Log {
    _private: (),
}

impl Log {
    /// Logs `message` at `level` with key-value `fields`.
    pub fn emit(&self, level: Level, message: &str, fields: &[(&str, &str)]) {
        let fields: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        log::emit(level, message, &fields);
    }

    /// Logs `message` at level trace.
    pub fn trace(&self, message: &str) {
        log::emit(Level::Trace, message, &[]);
    }

    /// Logs `message` at level debug.
    pub fn debug(&self, message: &str) {
        log::emit(Level::Debug, message, &[]);
    }

    /// Logs `message` at level info.
    pub fn info(&self, message: &str) {
        log::emit(Level::Info, message, &[]);
    }

    /// Logs `message` at level warn.
    pub fn warn(&self, message: &str) {
        log::emit(Level::Warn, message, &[]);
    }

    /// Logs `message` at level error.
    pub fn error(&self, message: &str) {
        log::emit(Level::Error, message, &[]);
    }
}
