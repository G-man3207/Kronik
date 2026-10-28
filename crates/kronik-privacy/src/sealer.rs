//! Sealing and unsealing log values (docs/design/m8-privacy.md §4, §5).
//!
//! The node holds one [`Sealer`]. While the mode is `on`, every `Sealable`
//! that carries a subject and is still plain is sealed with the subject's
//! newest key when its record is assembled; `off` costs one relaxed atomic
//! load. Reading goes through [`Sealer::open`], which returns the plaintext,
//! or says that the subject was erased or that the key is not here.
//!
//! Unwrapped keys are cached per (subject, version), bounded; erasing a
//! subject drops its keys from the cache. Nonces and new keys come from the
//! caller's randomness (`Env::random_bytes`, ADR 0004).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use crate::PrivacyError;
use crate::keystore::{KeyLookup, Keystore, Pseudonyms, SealedValue, SubjectKey, seal, unseal};

/// Unwrapped keys kept in memory at most.
const CACHE_KEYS: usize = 4096;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What reading a `Sealable` gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened<'a> {
    /// The value: recorded plain, or unsealed.
    Value(Cow<'a, [u8]>),
    /// Sealed for a subject that was erased: gone for good.
    Erased { subject: String },
    /// Sealed, and this keystore has no key for it (or the value is
    /// damaged). Not the same as erased: a restored keystore may have it.
    Unreadable { subject: String, why: String },
}

impl Opened<'_> {
    /// The bytes, if readable.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Opened::Value(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_owned(self) -> Option<Vec<u8>> {
        match self {
            Opened::Value(v) => Some(v.into_owned()),
            _ => None,
        }
    }
}

/// Why a value could not be unsealed for a guest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    // The messages leave the subject out: they reach turn outcomes, which
    // callers without pii:read read (M3). The subject stays in the value.
    #[error("SUBJECT_ERASED: a value of an erased subject")]
    Erased(String),
    #[error("a sealed value cannot be unsealed: {why}")]
    Missing { subject: String, why: String },
}

/// The node's sealing state: the mode and the keystore.
pub struct Sealer {
    on: AtomicBool,
    keystore: Option<Arc<Keystore>>,
    /// (subject, version) → key; the newest version per subject seals.
    cache: Mutex<BTreeMap<(String, u32), SubjectKey>>,
    newest: Mutex<BTreeMap<String, u32>>,
    /// For `--no-pii` forks (§9).
    pseudonyms: Option<Pseudonyms>,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("on", &self.is_on())
            .field("keystore", &self.keystore.is_some())
            .finish()
    }
}

/// Randomness for keys and nonces (`Env::entropy`).
/// What resealing one value did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResealOp {
    Unchanged,
    /// A tagged plain value, sealed with the subject's current key.
    Sealed,
    /// An erased subject's value, replaced by a tombstone.
    Tombstone,
}

fn tombstone(version: u32) -> pb::Sealed {
    pb::Sealed {
        key_version: version,
        nonce: vec![0; 24],
        ciphertext: Vec::new(),
    }
}

fn is_tombstone(s: &pb::Sealable, version: u32) -> bool {
    matches!(
        &s.value,
        Some(pb::sealable::Value::Sealed(x))
            if x.key_version == version && x.ciphertext.is_empty() && x.nonce.iter().all(|b| *b == 0)
    )
}

pub type Fill<'a> = &'a dyn Fn(&mut [u8]);

impl Sealer {
    /// A sealer with a keystore, starting `off` (the node sets the mode
    /// from the latest `PrivacyMode` record).
    pub fn new(keystore: Arc<Keystore>) -> Sealer {
        Sealer {
            on: AtomicBool::new(false),
            keystore: Some(keystore),
            cache: Mutex::new(BTreeMap::new()),
            newest: Mutex::new(BTreeMap::new()),
            pseudonyms: None,
        }
    }

    /// Adds the pseudonym key (derived from the master key).
    pub fn with_pseudonyms(mut self, p: Pseudonyms) -> Sealer {
        self.pseudonyms = Some(p);
        self
    }

    /// The pseudonym of a value of `subject`, when the key is here.
    pub fn pseudonym(&self, subject: &str, value: &[u8]) -> Option<String> {
        self.pseudonyms.as_ref().map(|p| p.of(subject, value))
    }

    /// A hash keyed with a master-derived key ([`Pseudonyms::keyed_hash`]),
    /// when the key is here (None for [`Sealer::plain`]).
    pub fn keyed_hash(&self, purpose: &str, parts: &[&[u8]]) -> Option<[u8; 32]> {
        self.pseudonyms
            .as_ref()
            .map(|p| p.keyed_hash(purpose, parts))
    }

    /// The fingerprint recorded for an effect: for a request of a subject,
    /// with the key here, `0x02` and a keyed hash of `fp` (the fingerprint
    /// sits next to the sealed request and must not confirm a guess of it);
    /// otherwise `fp` as it is.
    pub fn effect_fingerprint(&self, subject: Option<&str>, fp: Vec<u8>) -> Vec<u8> {
        match (
            subject,
            self.keyed_hash("kronik effect fingerprint v2", &[&fp]),
        ) {
            (Some(_), Some(k)) => {
                let mut out = Vec::with_capacity(33);
                out.push(2);
                out.extend_from_slice(&k);
                out
            }
            _ => fp,
        }
    }

    /// Whether a recorded fingerprint is that of the effect whose plain
    /// fingerprint is `fp`: keyed ([`Sealer::effect_fingerprint`]) or, for
    /// records written before keyed fingerprints, plain.
    pub fn fingerprint_matches(&self, subject: Option<&str>, recorded: &[u8], fp: &[u8]) -> bool {
        recorded == fp || recorded == self.effect_fingerprint(subject, fp.to_vec()).as_slice()
    }

    /// Without a keystore (tests, the simulator): never seals; sealed
    /// values read as unreadable.
    pub fn plain() -> Sealer {
        Sealer {
            on: AtomicBool::new(false),
            keystore: None,
            cache: Mutex::new(BTreeMap::new()),
            newest: Mutex::new(BTreeMap::new()),
            pseudonyms: None,
        }
    }

    pub fn keystore(&self) -> Option<&Arc<Keystore>> {
        self.keystore.as_ref()
    }

    /// The mode by time of writing (§3). One relaxed load.
    #[inline]
    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Turns sealing on or off; without a keystore it stays off.
    pub fn set_on(&self, on: bool) {
        self.on
            .store(on && self.keystore.is_some(), Ordering::Relaxed);
    }

    /// Drops a subject's cached keys (after erase or rotate).
    pub fn forget(&self, subject: &str) {
        lock(&self.cache).retain(|(s, _), _| s != subject);
        lock(&self.newest).remove(subject);
    }

    fn cache_put(&self, subject: &str, key: &SubjectKey) {
        let mut c = lock(&self.cache);
        if c.len() >= CACHE_KEYS {
            c.clear();
            lock(&self.newest).clear();
        }
        c.insert((subject.to_owned(), key.version), key.clone());
    }

    fn sealing_key(
        &self,
        ks: &Keystore,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        if let Some(v) = lock(&self.newest).get(subject).copied()
            && let Some(k) = lock(&self.cache).get(&(subject.to_owned(), v))
        {
            return Ok(k.clone());
        }
        let mut fresh = [0u8; 32];
        let mut nonce = [0u8; 24];
        fill(&mut fresh);
        fill(&mut nonce);
        let key = ks.key_for_sealing(subject, fresh, nonce, wall_ms)?;
        self.cache_put(subject, &key);
        lock(&self.newest).insert(subject.to_owned(), key.version);
        Ok(key)
    }

    fn opening_key(&self, subject: &str, version: u32) -> Result<KeyLookup, PrivacyError> {
        if let Some(k) = lock(&self.cache).get(&(subject.to_owned(), version)) {
            return Ok(KeyLookup::Found(k.clone()));
        }
        let Some(ks) = &self.keystore else {
            return Ok(KeyLookup::Missing);
        };
        let found = ks.key(subject, version)?;
        if let KeyLookup::Found(k) = &found {
            self.cache_put(subject, k);
        }
        Ok(found)
    }

    /// Seals one value in place if the mode is on, the value has a subject
    /// and it is still plain.
    pub fn seal_value(
        &self,
        s: &mut pb::Sealable,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<(), PrivacyError> {
        if !self.is_on() {
            return Ok(());
        }
        let (Some(subject), Some(pb::sealable::Value::Plain(plain))) = (&s.subject, &s.value)
        else {
            return Ok(());
        };
        let Some(ks) = &self.keystore else {
            return Ok(());
        };
        let key = self.sealing_key(ks, subject, fill, wall_ms)?;
        let mut nonce = [0u8; 24];
        fill(&mut nonce);
        let sealed = seal(subject, &key, nonce, plain)?;
        s.value = Some(pb::sealable::Value::Sealed(pb::Sealed {
            key_version: sealed.key_version,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        }));
        Ok(())
    }

    /// Seals every tagged plain value of a record (TurnBegin, EffectResult,
    /// TurnRecord) when the mode is on. `off`: one load, nothing else.
    pub fn seal_record(
        &self,
        r: &mut Record,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<(), PrivacyError> {
        if !self.is_on() {
            return Ok(());
        }
        let mut err = None;
        kronik_proto::sealables::record_mut(r, &mut |s| {
            if err.is_none()
                && let Err(e) = self.seal_value(s, fill, wall_ms)
            {
                err = Some(e);
            }
        });
        err.map_or(Ok(()), Err)
    }
    /// Reseals one value in place (docs/design/m8-privacy.md §8).
    ///
    /// Does not look at the mode: the caller has already required `on`.
    /// An erased subject's value (`erased_version`) becomes a tombstone
    /// that can never unseal; a tagged plain value is sealed with the
    /// subject's current key; anything else is left as recorded.
    pub fn reseal_value(
        &self,
        s: &mut pb::Sealable,
        erased_version: Option<u32>,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<ResealOp, PrivacyError> {
        let Some(subject) = s.subject.clone() else {
            return Ok(ResealOp::Unchanged);
        };
        if let Some(version) = erased_version {
            if is_tombstone(s, version) {
                return Ok(ResealOp::Unchanged);
            }
            s.value = Some(pb::sealable::Value::Sealed(tombstone(version)));
            return Ok(ResealOp::Tombstone);
        }
        if !matches!(s.value, Some(pb::sealable::Value::Plain(_))) {
            return Ok(ResealOp::Unchanged);
        }
        let Some(ks) = &self.keystore else {
            return Err(PrivacyError::Decrypt("reseal needs a keystore".into()));
        };
        let plain = match &s.value {
            Some(pb::sealable::Value::Plain(b)) => b.clone(),
            _ => return Ok(ResealOp::Unchanged),
        };
        let key = self.sealing_key(ks, &subject, fill, wall_ms)?;
        let mut nonce = [0u8; 24];
        fill(&mut nonce);
        let sealed = seal(&subject, &key, nonce, &plain)?;
        s.value = Some(pb::sealable::Value::Sealed(pb::Sealed {
            key_version: sealed.key_version,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        }));
        Ok(ResealOp::Sealed)
    }

    /// Reads a value. Plain values borrow; sealed ones are unsealed.
    pub fn open<'a>(&self, s: &'a pb::Sealable) -> Opened<'a> {
        let sealed = match &s.value {
            Some(pb::sealable::Value::Plain(b)) => return Opened::Value(Cow::Borrowed(b)),
            None => return Opened::Value(Cow::Borrowed(&[])),
            Some(pb::sealable::Value::Sealed(x)) => x,
        };
        let subject = s.subject.clone().unwrap_or_default();
        let unreadable = |why: String| Opened::Unreadable {
            subject: subject.clone(),
            why,
        };
        let Ok(nonce) = <[u8; 24]>::try_from(sealed.nonce.as_slice()) else {
            // A tombstone (§8) or a damaged value.
            return if sealed.ciphertext.is_empty() {
                Opened::Erased {
                    subject: subject.clone(),
                }
            } else {
                unreadable("bad nonce".into())
            };
        };
        match self.opening_key(&subject, sealed.key_version) {
            Ok(KeyLookup::Found(k)) => {
                let v = SealedValue {
                    key_version: sealed.key_version,
                    nonce,
                    ciphertext: sealed.ciphertext.clone(),
                };
                match unseal(&subject, &k, &v) {
                    Ok(plain) => Opened::Value(Cow::Owned(plain)),
                    Err(e) => unreadable(e.to_string()),
                }
            }
            Ok(KeyLookup::Erased) => Opened::Erased { subject },
            Ok(KeyLookup::Missing) => unreadable(format!(
                "no key version {} in this keystore",
                sealed.key_version
            )),
            Err(e) => unreadable(e.to_string()),
        }
    }

    /// Unseals one value in place for a guest.
    pub fn unseal_value(&self, s: &mut pb::Sealable) -> Result<(), Unreadable> {
        if !matches!(s.value, Some(pb::sealable::Value::Sealed(_))) {
            return Ok(());
        }
        match self.open(s) {
            Opened::Value(v) => {
                let v = v.into_owned();
                s.value = Some(pb::sealable::Value::Plain(v));
                Ok(())
            }
            Opened::Erased { subject } => Err(Unreadable::Erased(subject)),
            Opened::Unreadable { subject, why } => Err(Unreadable::Missing { subject, why }),
        }
    }

    /// Unseals every value of an input in place (what a turn hands its
    /// guest). The first unreadable value is the error.
    pub fn unseal_input(&self, input: &mut pb::Input) -> Result<(), Unreadable> {
        let mut err = None;
        kronik_proto::sealables::input_mut(Some(input), &mut |s| {
            if err.is_none()
                && let Err(e) = self.unseal_value(s)
            {
                err = Some(e);
            }
        });
        err.map_or(Ok(()), Err)
    }

    /// Unseals every value of a record in place; unreadable values stay as
    /// they are and are counted.
    pub fn unseal_record(&self, r: &mut Record) -> usize {
        let mut failed = 0;
        kronik_proto::sealables::record_mut(r, &mut |s| {
            if self.unseal_value(s).is_err() {
                failed += 1;
            }
        });
        failed
    }

    /// Erases a subject (§6.1): its keys first, durably; returns the last
    /// erased version (0 when it had none).
    /// Every erased subject in the keystore (none without one).
    pub fn erasures(&self) -> Result<Vec<crate::keystore::ErasureInfo>, PrivacyError> {
        match &self.keystore {
            Some(ks) => ks.erasures(),
            None => Ok(Vec::new()),
        }
    }

    pub fn erase(&self, subject: &str, wall_ms: u64) -> Result<u32, PrivacyError> {
        let Some(ks) = &self.keystore else {
            return Ok(0);
        };
        let v = ks.erase(subject, wall_ms)?;
        self.forget(subject);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;

    fn sealer(dir: &std::path::Path) -> Sealer {
        let (master, _) = MasterKey::load_or_create(&dir.join("master.key"), [7; 32]).unwrap();
        let conn = rusqlite::Connection::open(dir.join("keystore.db")).unwrap();
        Sealer::new(Arc::new(Keystore::open(conn, &master).unwrap()))
    }

    fn counter_fill() -> impl Fn(&mut [u8]) {
        let n = std::sync::atomic::AtomicU8::new(1);
        move |b: &mut [u8]| {
            let x = n.fetch_add(1, Ordering::Relaxed);
            b.fill(x);
        }
    }

    fn val(subject: Option<&str>, v: &[u8]) -> pb::Sealable {
        pb::Sealable {
            subject: subject.map(str::to_owned),
            value: Some(pb::sealable::Value::Plain(v.to_vec())),
        }
    }

    #[test]
    fn off_seals_nothing_and_on_seals_tagged_values() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        let fill = counter_fill();
        let mut r = Record::TurnRecord(pb::TurnRecord {
            writes: vec![
                pb::StateWrite {
                    value: Some(val(Some("user:1"), b"alice")),
                    ..Default::default()
                },
                pb::StateWrite {
                    value: Some(val(None, b"shared")),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let before = r.clone();
        s.seal_record(&mut r, &fill, 1).unwrap();
        assert_eq!(r, before, "off changes nothing");
        s.set_on(true);
        s.seal_record(&mut r, &fill, 1).unwrap();
        let Record::TurnRecord(t) = r.clone() else {
            panic!()
        };
        let tagged = t.writes[0].value.as_ref().unwrap();
        assert!(matches!(tagged.value, Some(pb::sealable::Value::Sealed(_))));
        assert_eq!(t.writes[1].value, before_untagged(&before));
        assert_eq!(s.open(tagged).bytes(), Some(&b"alice"[..]));
        // Sealing again leaves sealed values alone.
        let again = r.clone();
        s.seal_record(&mut r, &fill, 1).unwrap();
        assert_eq!(r, again);
        // Erase: unreadable for good, even after a new key.
        assert_eq!(s.erase("user:1", 2).unwrap(), 1);
        assert_eq!(
            s.open(tagged),
            Opened::Erased {
                subject: "user:1".into()
            }
        );
        let mut v = tagged.clone();
        assert_eq!(
            s.unseal_value(&mut v),
            Err(Unreadable::Erased("user:1".into()))
        );
        let mut fresh = val(Some("user:1"), b"bob");
        s.seal_value(&mut fresh, &fill, 3).unwrap();
        assert_eq!(s.open(&fresh).bytes(), Some(&b"bob"[..]));
        // Another subject is unaffected.
        let mut other = val(Some("user:2"), b"carol");
        s.seal_value(&mut other, &fill, 3).unwrap();
        s.erase("user:1", 4).unwrap();
        assert_eq!(s.open(&other).bytes(), Some(&b"carol"[..]));
    }

    fn before_untagged(r: &Record) -> Option<pb::Sealable> {
        let Record::TurnRecord(t) = r else {
            return None;
        };
        t.writes[1].value.clone()
    }

    #[test]
    fn a_plain_sealer_never_seals_and_cannot_open() {
        let s = Sealer::plain();
        s.set_on(true);
        assert!(!s.is_on());
        let dir = tempfile::tempdir().unwrap();
        let real = sealer(dir.path());
        real.set_on(true);
        let mut v = val(Some("user:1"), b"x");
        real.seal_value(&mut v, &counter_fill(), 1).unwrap();
        assert!(matches!(s.open(&v), Opened::Unreadable { .. }));
    }

    /// M6: the fingerprint of a subject's request is keyed (it sits next
    /// to the sealed request), so it is not the plain fingerprint and needs
    /// the master-derived key; records with plain fingerprints still match.
    #[test]
    fn a_subjects_fingerprint_is_keyed() {
        let keyed =
            Sealer::plain().with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([1; 32])));
        let other =
            Sealer::plain().with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([2; 32])));
        let fp = blake3::hash(b"POST /v1/pay alice@example.com")
            .as_bytes()
            .to_vec();
        let k = keyed.effect_fingerprint(Some("user:1"), fp.clone());
        assert_eq!((k.len(), k[0]), (33, 2));
        assert_ne!(k[1..], fp[..]);
        assert_ne!(k, other.effect_fingerprint(Some("user:1"), fp.clone()));
        // Without a subject, or without the key: the plain fingerprint.
        assert_eq!(keyed.effect_fingerprint(None, fp.clone()), fp);
        assert_eq!(
            Sealer::plain().effect_fingerprint(Some("user:1"), fp.clone()),
            fp
        );
        assert!(keyed.fingerprint_matches(Some("user:1"), &k, &fp));
        assert!(keyed.fingerprint_matches(Some("user:1"), &fp, &fp));
        assert!(!other.fingerprint_matches(Some("user:1"), &k, &fp));
    }
}
