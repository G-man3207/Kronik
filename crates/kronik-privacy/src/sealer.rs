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
use zeroize::{Zeroize, Zeroizing};

use kronik_core::sync::lock;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use kronik_blob::{BlobKeys, KeyAnswer};

use crate::PrivacyError;
use crate::keystore::{
    KeyLookup, KeyRevision, Keystore, Pseudonyms, SealedValue, SubjectKey, seal, unseal,
};

mod prepared;

/// Unwrapped keys kept in memory at most.
const CACHE_KEYS: usize = 4096;

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
    /// Keys, their newest-version index, and erasure history share one revision.
    cache: Mutex<KeyCache>,
    /// For `--no-pii` forks (§9).
    pseudonyms: Option<Pseudonyms>,
}

#[derive(Default)]
struct KeyCache {
    revision: Option<KeyRevision>,
    keys: BTreeMap<String, BTreeMap<u32, SubjectKey>>,
    key_count: usize,
    newest: BTreeMap<String, u32>,
    /// The oldest version that is not erased: the one blobs use (ADR 0118).
    oldest: BTreeMap<String, u32>,
    erasure_floors: BTreeMap<String, Option<u32>>,
}
impl KeyCache {
    fn clear(&mut self) {
        self.keys.clear();
        self.key_count = 0;
        self.newest.clear();
        self.oldest.clear();
        self.erasure_floors.clear();
        self.revision = None;
    }
    fn at(&mut self, revision: KeyRevision) {
        if self.revision != Some(revision) {
            self.clear();
            self.revision = Some(revision);
        }
    }
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

/// What a value of a subject erased through `version` becomes where it must
/// stay recorded outside the log (`state.db` rows, queued and in-flight
/// inputs, a fork's records): a `Sealed` that names the erased version with
/// an empty nonce and no ciphertext, so it opens as erased whatever the
/// keystore holds.
pub fn erased_value(version: u32) -> pb::Sealed {
    pb::Sealed {
        key_version: version,
        nonce: Vec::new(),
        ciphertext: Vec::new(),
    }
}

/// Whether `s` is an erased subject's tombstone ([`erased_value`], or the
/// form a reseal of the log leaves): a sealed value without ciphertext. A
/// value sealed under a key always has one, its AEAD tag at least.
pub fn is_erased(s: &pb::Sealable) -> bool {
    matches!(&s.value, Some(pb::sealable::Value::Sealed(x)) if x.ciphertext.is_empty())
}

fn tombstone(version: u32) -> pb::Sealed {
    pb::Sealed {
        key_version: version,
        nonce: vec![0; 24],
        ciphertext: Vec::new(),
    }
}

/// Whether a sealed value is the tombstone `version` seals after erasure:
/// empty ciphertext and an all-zero nonce under that key version. The
/// reseal scan shares it, so a tombstone the sealer wrote is one it skips.
pub fn is_tombstone(s: &pb::Sealable, version: u32) -> bool {
    matches!(
        &s.value,
        Some(pb::sealable::Value::Sealed(x))
            if x.key_version == version && x.ciphertext.is_empty() && x.nonce.iter().all(|b| *b == 0)
    )
}

pub type Fill<'a> = &'a dyn Fn(&mut [u8]);

/// The context of the key derived from a subject key to key the identities
/// of the subject's blobs (ADR 0118 §1).
pub const BLOB_IDENTITY_LABEL: &str = "kronik blob identity v1";
/// The context of the key derived from a subject key to seal the frames of
/// the subject's blobs (ADR 0117 §2). Values are sealed with the subject key
/// itself, so no two uses share a key.
pub const BLOB_SEAL_LABEL: &str = "kronik blob seal v1";

/// Keys for reading subjects' blobs: exact versions, never created
/// ([`Sealer::blob_key_access`]).
pub struct BlobKeyAccess<'a>(&'a Sealer);

impl kronik_blob::KeyAccess for BlobKeyAccess<'_> {
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer {
        self.0.blob_key(subject, version, BLOB_SEAL_LABEL)
    }

    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer {
        self.0.blob_key(subject, version, BLOB_IDENTITY_LABEL)
    }
}

impl Sealer {
    /// A sealer with a keystore, starting `off` (the node sets the mode
    /// from the latest `PrivacyMode` record).
    pub fn new(keystore: Arc<Keystore>) -> Sealer {
        Sealer {
            on: AtomicBool::new(false),
            keystore: Some(keystore),
            cache: Mutex::new(KeyCache::default()),
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
            cache: Mutex::new(KeyCache::default()),
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
        let mut cache = lock(&self.cache);
        if let Some(versions) = cache.keys.remove(subject) {
            cache.key_count -= versions.len();
        }
        cache.newest.remove(subject);
        cache.oldest.remove(subject);
        cache.erasure_floors.remove(subject);
    }

    fn cache_at_revision(
        &self,
        ks: &Keystore,
    ) -> Result<std::sync::MutexGuard<'_, KeyCache>, PrivacyError> {
        let revision = match ks.cache_revision() {
            Ok(revision) => revision,
            Err(error) => {
                lock(&self.cache).clear();
                return Err(error);
            }
        };
        let mut cache = lock(&self.cache);
        cache.at(revision);
        Ok(cache)
    }

    fn cache_put(&self, subject: &str, key: &SubjectKey, revision: KeyRevision, sealing: bool) {
        let mut cache = lock(&self.cache);
        if cache.key_count >= CACHE_KEYS {
            cache.clear();
        }
        cache.at(revision);
        let added = if let Some(versions) = cache.keys.get_mut(subject) {
            if let std::collections::btree_map::Entry::Vacant(entry) = versions.entry(key.version) {
                entry.insert(key.clone());
                true
            } else {
                false
            }
        } else {
            cache.keys.insert(
                subject.to_owned(),
                BTreeMap::from([(key.version, key.clone())]),
            );
            true
        };
        cache.key_count += usize::from(added);
        if sealing {
            if let Some(version) = cache.newest.get_mut(subject) {
                *version = key.version;
            } else {
                cache.newest.insert(subject.to_owned(), key.version);
            }
        }
    }

    fn sealing_key(
        &self,
        ks: &Keystore,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        {
            let cache = self.cache_at_revision(ks)?;
            if let Some(version) = cache.newest.get(subject)
                && let Some(key) = cache
                    .keys
                    .get(subject)
                    .and_then(|versions| versions.get(version))
            {
                return Ok(key.clone());
            }
        }
        self.load_sealing_key(ks, subject, fill, wall_ms)
    }

    fn load_sealing_key(
        &self,
        ks: &Keystore,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        let mut fresh = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        fill(&mut fresh[..]);
        fill(&mut nonce);
        let (revision, key) = match ks.sealing_key_at_revision(subject, *fresh, nonce, wall_ms) {
            Ok(found) => found,
            Err(error) => {
                lock(&self.cache).clear();
                return Err(error);
            }
        };
        self.cache_put(subject, &key, revision, true);
        Ok(key)
    }

    fn opening_key(&self, subject: &str, version: u32) -> Result<KeyLookup, PrivacyError> {
        let Some(ks) = &self.keystore else {
            return Ok(KeyLookup::Missing);
        };
        {
            let cache = self.cache_at_revision(ks)?;
            if let Some(key) = cache
                .keys
                .get(subject)
                .and_then(|versions| versions.get(&version))
            {
                return Ok(KeyLookup::Found(key.clone()));
            }
        }
        self.load_opening_key(ks, subject, version)
    }

    fn load_opening_key(
        &self,
        ks: &Keystore,
        subject: &str,
        version: u32,
    ) -> Result<KeyLookup, PrivacyError> {
        let (revision, found) = match ks.key_at_revision(subject, version) {
            Ok(found) => found,
            Err(error) => {
                lock(&self.cache).clear();
                return Err(error);
            }
        };
        if let KeyLookup::Found(key) = &found {
            self.cache_put(subject, key, revision, false);
        }
        Ok(found)
    }

    /// The keys of `subject`'s blobs (ADR 0118 §1, ADR 0117 §2): the identity
    /// key and, while the mode is on, the frame key, both derived from the
    /// subject's oldest key version that is not erased. A subject without a
    /// key gets one, in either mode (the only keystore write in mode off),
    /// so that an erasure can later unlink its blobs' identities. Without a
    /// keystore (tests, the simulator) the keys come from a fixed test key
    /// of version 1 and nothing is sealed.
    pub fn blob_keys(
        &self,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<BlobKeys, PrivacyError> {
        if !crate::keystore::valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let Some(ks) = &self.keystore else {
            let key = crate::keystore::test_subject_key(subject);
            return Ok(BlobKeys {
                subject: subject.to_owned(),
                key_version: key.version,
                identity: key.derive(BLOB_IDENTITY_LABEL),
                seal: None,
            });
        };
        let key = self.blob_identity_key(ks, subject, fill, wall_ms)?;
        Ok(BlobKeys {
            subject: subject.to_owned(),
            key_version: key.version,
            identity: key.derive(BLOB_IDENTITY_LABEL),
            seal: self.is_on().then(|| key.derive(BLOB_SEAL_LABEL)),
        })
    }

    /// [`Sealer::blob_keys`] without creating a key: `None` when the
    /// subject has no live key ([`Sealer::fork_blob_keys`] then decides).
    /// Without a keystore, the test key.
    pub fn existing_blob_keys(&self, subject: &str) -> Result<Option<BlobKeys>, PrivacyError> {
        if !crate::keystore::valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let key = match &self.keystore {
            None => Some(crate::keystore::test_subject_key(subject)),
            Some(ks) => ks.existing_identity_key(subject)?,
        };
        Ok(key.map(|key| BlobKeys {
            subject: subject.to_owned(),
            key_version: key.version,
            identity: key.derive(BLOB_IDENTITY_LABEL),
            seal: (self.keystore.is_some() && self.is_on()).then(|| key.derive(BLOB_SEAL_LABEL)),
        }))
    }

    /// The keys of a subject's blob that a fork writes (a preview's upload,
    /// a fork turn's writer), by the rule of the fork's own record sealing
    /// ([`Sealer::keep_erased_without_keys`]): with the mode on, the
    /// subject's key, created when it has none and was never erased, as the
    /// fork's record that names the blob creates it; `None` when it was
    /// erased and has no key newer than its erasure, as a fork never makes a
    /// key version for an erased subject (M8 §6.8). With the mode off nothing
    /// is sealed and the keystore is not written: the existing key, else the
    /// fixed test key.
    pub fn fork_blob_keys(
        &self,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<Option<BlobKeys>, PrivacyError> {
        if let Some(keys) = self.existing_blob_keys(subject)? {
            return Ok(Some(keys));
        }
        if self.keystore.is_none() || !self.is_on() {
            return Sealer::plain()
                .blob_keys(subject, &|bytes: &mut [u8]| bytes.fill(0), 0)
                .map(Some);
        }
        if self.erasure_floor(subject)?.is_some() {
            return Ok(None);
        }
        self.blob_keys(subject, fill, wall_ms).map(Some)
    }

    fn blob_identity_key(
        &self,
        ks: &Keystore,
        subject: &str,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        {
            let cache = self.cache_at_revision(ks)?;
            if let Some(version) = cache.oldest.get(subject)
                && let Some(key) = cache
                    .keys
                    .get(subject)
                    .and_then(|versions| versions.get(version))
            {
                return Ok(key.clone());
            }
        }
        let mut fresh = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        fill(&mut fresh[..]);
        fill(&mut nonce);
        let (revision, key) = match ks.identity_key_at_revision(subject, *fresh, nonce, wall_ms) {
            Ok(found) => found,
            Err(error) => {
                lock(&self.cache).clear();
                return Err(error);
            }
        };
        self.cache_put(subject, &key, revision, false);
        let mut cache = lock(&self.cache);
        if cache.revision == Some(revision) {
            cache.oldest.insert(subject.to_owned(), key.version);
        }
        Ok(key)
    }

    /// Keys for reading subjects' blobs ([`kronik_blob::KeyAccess`]): the
    /// exact version a blob names, never created and never the newest.
    pub fn blob_key_access(&self) -> BlobKeyAccess<'_> {
        BlobKeyAccess(self)
    }

    fn blob_key(&self, subject: &str, version: u32, label: &str) -> KeyAnswer {
        if version == 0 || !crate::keystore::valid_subject(subject) {
            return KeyAnswer::Missing;
        }
        if self.keystore.is_none() {
            // Without a keystore nothing is sealed: a sealed blob needs a key
            // this sealer does not have (KEYSTORE_INCOMPLETE).
            let key = crate::keystore::test_subject_key(subject);
            return if label == BLOB_IDENTITY_LABEL && version == key.version {
                KeyAnswer::Found(key.derive(label))
            } else {
                KeyAnswer::Missing
            };
        }
        match self.opening_key(subject, version) {
            Ok(KeyLookup::Found(key)) => KeyAnswer::Found(key.derive(label)),
            Ok(KeyLookup::Erased) => KeyAnswer::Erased,
            Ok(KeyLookup::Missing) => KeyAnswer::Missing,
            Err(error) => KeyAnswer::Unavailable(error.to_string()),
        }
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
        let previous = s.value.replace(pb::sealable::Value::Sealed(pb::Sealed {
            key_version: sealed.key_version,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        }));
        if let Some(pb::sealable::Value::Plain(mut plain)) = previous {
            plain.zeroize();
        }
        Ok(())
    }

    /// Returns this local keystore's observed historical erasure floor. A real
    /// zero floor is `Some(0)`; `None` is not a SourcePos or complete-history
    /// proof. An active newer key never proves old plaintext was post-erasure.
    pub fn erasure_floor(&self, subject: &str) -> Result<Option<u32>, PrivacyError> {
        if !crate::keystore::valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let Some(ks) = &self.keystore else {
            return Err(PrivacyError::Decrypt(
                "erasure history needs a keystore".into(),
            ));
        };
        {
            let cache = self.cache_at_revision(ks)?;
            if let Some(floor) = cache.erasure_floors.get(subject) {
                return Ok(*floor);
            }
        }
        let (revision, floor) = match ks.erasure_floor_at_revision(subject) {
            Ok(found) => found,
            Err(error) => {
                lock(&self.cache).clear();
                return Err(error);
            }
        };
        let mut cache = lock(&self.cache);
        cache.at(revision);
        if cache.erasure_floors.len() >= CACHE_KEYS {
            cache.erasure_floors.clear();
        }
        cache.erasure_floors.insert(subject.to_owned(), floor);
        Ok(floor)
    }

    /// Tombstones every value of `r` whose subject was erased and has no key
    /// version newer than the erasure: a fork never makes one for an erased
    /// subject (M8 §6.8). A subject that came back keeps its values for
    /// [`Sealer::seal_record`], under its new key.
    ///
    /// The caller must already have tombstoned the values that predate their
    /// subject's erasure from the record's provenance; this is the rest of
    /// the fork rule, not a substitute for that provenance. Returns how many
    /// values it replaced.
    pub fn keep_erased_without_keys(&self, r: &mut Record) -> Result<u64, PrivacyError> {
        let Some(ks) = &self.keystore else {
            return Ok(0);
        };
        let mut err = None;
        let mut replaced = 0;
        kronik_proto::sealables::record_mut(r, &mut |s| {
            if err.is_some() {
                return;
            }
            let Some(subject) = &s.subject else {
                return;
            };
            let floor = match self.erasure_floor(subject) {
                Ok(Some(floor)) => floor,
                Ok(None) => return,
                Err(e) => {
                    err = Some(e);
                    return;
                }
            };
            match ks.newest_version(subject) {
                Ok(None) => {}
                Ok(Some(_)) => return,
                Err(e) => {
                    err = Some(e);
                    return;
                }
            }
            let tombstone = pb::sealable::Value::Sealed(erased_value(floor));
            if s.value.as_ref() != Some(&tombstone) {
                if let Some(pb::sealable::Value::Plain(mut plain)) = s.value.replace(tombstone) {
                    plain.zeroize();
                }
                replaced += 1;
            }
        });
        err.map_or(Ok(replaced), Err)
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

    /// Unseals a saved answer (an ingress response that an idempotent retry
    /// gets back) in place for its requester: a value whose subject was
    /// erased becomes that erasure's tombstone ([`erased_value`], see
    /// [`is_erased`]), as in the live answer of a turn that ran across the
    /// erasure (ADR 0123); a value unreadable for another reason stays as it
    /// is.
    pub fn unseal_answer(&self, outcome: &mut pb::Outcome) {
        kronik_proto::sealables::outcome_mut(Some(outcome), &mut |s| {
            if let Err(Unreadable::Erased(_)) = self.unseal_value(s)
                && let Some(pb::sealable::Value::Sealed(x)) = &s.value
            {
                let version = x.key_version;
                s.value = Some(pb::sealable::Value::Sealed(erased_value(version)));
            }
        });
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
        let result = ks.erase(subject, wall_ms);
        lock(&self.cache).clear();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;

    fn sealer(dir: &std::path::Path) -> Sealer {
        let owner = crate::key_source::lock_data(dir).unwrap();
        let (master, _) = MasterKey::open(&dir.join("master.key"), dir, Some([7; 32])).unwrap();
        Sealer::new(Keystore::open_owned(&owner, &master).unwrap())
    }

    fn counter_fill() -> impl Fn(&mut [u8]) {
        let n = std::sync::atomic::AtomicU8::new(1);
        move |b: &mut [u8]| {
            let x = n.fetch_add(1, Ordering::Relaxed);
            b.fill(x);
        }
    }

    /// A record whose caller knows its provenance (the node's fork sealing)
    /// keeps the tombstones of erased subjects, seals a subject that was
    /// never erased, and seals one that came back under its new key.
    #[test]
    fn a_forks_record_with_provenance_keeps_tombstones_and_seals_the_living() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.set_on(true);
        let fill = counter_fill();
        let mut seed = val(Some("user:1"), b"x");
        s.seal_value(&mut seed, &fill, 1).unwrap();
        s.erase("user:1", 2).unwrap();
        let mut back = val(Some("user:3"), b"x");
        s.seal_value(&mut back, &fill, 3).unwrap();
        s.erase("user:3", 4).unwrap();
        let mut again = val(Some("user:3"), b"y");
        s.seal_value(&mut again, &fill, 5).unwrap();
        // A caller that knows the erasure copies the tombstone; what is new
        // and was never erased still seals, and a subject that came back
        // seals under its new key.
        let mut provided = Record::TurnRecord(pb::TurnRecord {
            writes: vec![
                pb::StateWrite {
                    key: "a".into(),
                    op: pb::StateOp::Set as i32,
                    value: Some(pb::Sealable {
                        subject: Some("user:1".into()),
                        value: Some(pb::sealable::Value::Sealed(erased_value(1))),
                    }),
                },
                pb::StateWrite {
                    key: "b".into(),
                    op: pb::StateOp::Set as i32,
                    value: Some(val(Some("user:2"), b"never erased")),
                },
                pb::StateWrite {
                    key: "c".into(),
                    op: pb::StateOp::Set as i32,
                    value: Some(val(Some("user:3"), b"came back")),
                },
            ],
            ..Default::default()
        });
        s.seal_record(&mut provided, &fill, 6).unwrap();
        let Record::TurnRecord(t) = provided else {
            unreachable!()
        };
        let sealed = |i: usize| match t.writes[i].value.as_ref().and_then(|v| v.value.as_ref()) {
            Some(pb::sealable::Value::Sealed(x)) => x.clone(),
            other => panic!("not sealed: {other:?}"),
        };
        assert_eq!(sealed(0), erased_value(1));
        assert_eq!(sealed(1).key_version, 1);
        assert_eq!(sealed(2).key_version, 2, "user:3's key after its erasure");
        assert_eq!(
            s.open(t.writes[2].value.as_ref().unwrap()).bytes(),
            Some(&b"came back"[..])
        );
    }

    fn val(subject: Option<&str>, v: &[u8]) -> pb::Sealable {
        pb::Sealable::new_plain(subject.map(str::to_owned), v)
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

    /// M24: a connection turn's frame data, close reasons, open request
    /// and accept headers are sealed with their subject and unseal again.
    #[test]
    fn connection_values_seal_and_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.set_on(true);
        let fill = counter_fill();
        let conn = "c-0123456789abcdef0123456789abcdef".to_string();
        let frame = |data: &[u8]| pb::Frame {
            kind: pb::frame::Kind::Text as i32,
            data: Some(val(Some("user:1"), data)),
            ..Default::default()
        };
        let original = Record::TurnRecord(pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Connection(pb::ConnectionInput {
                    connection: conn.clone(),
                    protocol: pb::ConnectionProtocol::Websocket as i32,
                    event: Some(pb::connection_input::Event::Frame(pb::ConnectionFrame {
                        seq: 0,
                        frame: Some(frame(b"incoming")),
                    })),
                    ..Default::default()
                })),
            }),
            outcome: Some(pb::Outcome {
                output: Some(pb::outcome::Output::Accept(pb::ConnectionAccept {
                    headers: vec![pb::Header {
                        name: "x".into(),
                        value: Some(val(Some("user:1"), b"header")),
                    }],
                    ..Default::default()
                })),
                ..Default::default()
            }),
            connection_ops: vec![
                pb::ConnectionOp {
                    connections: vec![conn.clone()],
                    seqs: vec![0],
                    op: Some(pb::connection_op::Op::Send(frame(b"outgoing"))),
                    dropped: Vec::new(),
                },
                pb::ConnectionOp {
                    connections: vec![conn],
                    seqs: vec![],
                    op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
                        code: 1000,
                        reason: Some(val(Some("user:1"), b"bye")),
                    })),
                    dropped: Vec::new(),
                },
            ],
            ..Default::default()
        });
        let mut r = original.clone();
        s.seal_record(&mut r, &fill, 1).unwrap();
        let mut plain = 0;
        kronik_proto::sealables::record_mut(&mut r, &mut |v| {
            assert!(
                matches!(v.value, Some(pb::sealable::Value::Sealed(_))),
                "{v:?}"
            );
            plain += 1;
        });
        assert_eq!(plain, 4);
        assert_eq!(s.unseal_record(&mut r), 0, "none fails to unseal");
        assert_eq!(r, original);
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
        let keyed = Sealer::plain()
            .with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([1; 32]).unwrap()).unwrap());
        let other = Sealer::plain()
            .with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([2; 32]).unwrap()).unwrap());
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

    #[test]
    fn revision_tests_bound_erasure_floor_metadata_without_evicting_keys() {
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let ks = Arc::new(Keystore::open_memory(&master).unwrap());
        let s = Sealer::new(ks.clone());
        s.set_on(true);
        let mut value = val(Some("user:1"), b"cached key survives metadata eviction");
        s.seal_value(&mut value, &counter_fill(), 1).unwrap();
        let revision = ks.revision().unwrap();
        for index in 0..=CACHE_KEYS {
            assert_eq!(s.erasure_floor(&format!("probe:{index}")).unwrap(), None);
        }
        {
            let cache = lock(&s.cache);
            assert!(cache.erasure_floors.len() <= CACHE_KEYS);
        }
        assert_eq!(
            s.open(&value).bytes(),
            Some(b"cached key survives metadata eviction".as_slice())
        );
        assert_eq!(s.erasure_floor("user:1").unwrap(), None);
        assert!(lock(&s.cache).erasure_floors.contains_key("user:1"));
        s.forget("user:1");
        {
            let cache = lock(&s.cache);
            assert!(!cache.erasure_floors.contains_key("user:1"));
            assert!(
                cache
                    .erasure_floors
                    .contains_key(&format!("probe:{CACHE_KEYS}"))
            );
            assert!(cache.keys.is_empty());
            assert!(!cache.newest.contains_key("user:1"));
        }
        assert_eq!(s.erasure_floor("user:1").unwrap(), None);
        assert_eq!(
            s.open(&value).bytes(),
            Some(b"cached key survives metadata eviction".as_slice())
        );
        assert_eq!(ks.revision().unwrap(), revision);
        assert_eq!(ks.stats().unwrap().keys, 1);
        assert_eq!(ks.stats().unwrap().erased, 0);
    }

    /// ADR 0123: a saved answer that goes back to its requester after one of
    /// its subjects was erased holds that erasure's tombstone in place of the
    /// value, as the live answer of a turn that ran across the erasure does;
    /// another subject's value opens as usual.
    /// A reseal's tombstone of a subject that never had a key (erased
    /// through version 0) opens as erased, as one of a subject that had a
    /// key does. A tombstone of a subject this keystore never erased stays
    /// unreadable (it vouches for nothing), whatever version it names.
    #[test]
    fn a_tombstone_of_a_subject_that_never_had_a_key_opens_as_erased() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.set_on(true);
        assert_eq!(s.erase("user:8", 1).unwrap(), 0);
        let mut v = val(Some("user:8"), b"a request written in mode off");
        assert_eq!(
            s.reseal_value(&mut v, Some(0), &counter_fill(), 2).unwrap(),
            ResealOp::Tombstone
        );
        assert!(matches!(s.open(&v), Opened::Erased { .. }), "{v:?}");
        // A subject that had a key: erased through version 1.
        let mut had = val(Some("user:9"), b"x");
        s.seal_value(&mut had, &counter_fill(), 3).unwrap();
        assert_eq!(s.erase("user:9", 4).unwrap(), 1);
        assert!(matches!(s.open(&had), Opened::Erased { .. }));
        // Tombstones of a subject that was never erased.
        for version in [0, 1] {
            let forged = pb::Sealable {
                subject: Some("user:10".into()),
                value: Some(pb::sealable::Value::Sealed(tombstone(version))),
            };
            assert!(
                matches!(s.open(&forged), Opened::Unreadable { .. }),
                "{version}"
            );
        }
    }

    #[test]
    fn a_saved_answer_holds_the_tombstone_of_an_erased_subject() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.set_on(true);
        let fill = counter_fill();
        let mut body = val(Some("user:1"), b"alice");
        s.seal_value(&mut body, &fill, 1).unwrap();
        let mut header = val(Some("user:2"), b"bob");
        s.seal_value(&mut header, &fill, 2).unwrap();
        let answer = pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                status: 200,
                headers: vec![pb::Header {
                    name: "x-user".into(),
                    value: Some(header),
                }],
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(body)),
                }),
            })),
            ..Default::default()
        };
        let parts = |o: &pb::Outcome| match &o.output {
            Some(pb::outcome::Output::Http(h)) => (
                match h.body.as_ref().and_then(|b| b.value.clone()) {
                    Some(pb::body::Value::Inline(s)) => s,
                    other => panic!("{other:?}"),
                },
                h.headers[0].value.clone().unwrap(),
            ),
            other => panic!("{other:?}"),
        };
        let mut open = answer.clone();
        s.unseal_answer(&mut open);
        assert_eq!(
            parts(&open),
            (val(Some("user:1"), b"alice"), val(Some("user:2"), b"bob"))
        );
        s.erase("user:1", 3).unwrap();
        let mut after = answer;
        s.unseal_answer(&mut after);
        let (body, header) = parts(&after);
        assert!(is_erased(&body), "{body:?}");
        assert_eq!(body.subject.as_deref(), Some("user:1"));
        assert_eq!(header, val(Some("user:2"), b"bob"));
        assert!(!is_erased(&header));
    }
}

#[cfg(test)]
mod blob_key_tests {
    use super::*;
    use crate::MasterKey;
    use kronik_blob::KeyAccess as _;

    fn master() -> MasterKey {
        MasterKey::from_bytes([1; 32]).unwrap()
    }

    fn sealer() -> Sealer {
        Sealer::new(Arc::new(Keystore::open_memory(&master()).unwrap()))
    }

    fn fill(byte: u8) -> impl Fn(&mut [u8]) {
        move |b: &mut [u8]| b.fill(byte)
    }

    fn found(answer: KeyAnswer) -> Zeroizing<[u8; 32]> {
        match answer {
            KeyAnswer::Found(key) => key,
            KeyAnswer::Erased => panic!("erased"),
            KeyAnswer::Missing => panic!("missing"),
            KeyAnswer::Unavailable(why) => panic!("unavailable: {why}"),
        }
    }

    #[test]
    fn a_subjects_first_blob_creates_its_key_once_in_either_mode() {
        let s = sealer();
        let off = s.blob_keys("user:1", &fill(7), 1).unwrap();
        assert_eq!((off.subject.as_str(), off.key_version), ("user:1", 1));
        assert!(off.seal.is_none(), "mode off seals nothing");
        let again = s.blob_keys("user:1", &fill(8), 2).unwrap();
        assert_eq!(*again.identity, *off.identity);
        assert_eq!(s.keystore().unwrap().stats().unwrap().keys, 1);
        // The derivation is fixed: the subject key here is [7; 32].
        assert_eq!(
            *off.identity,
            blake3::derive_key(BLOB_IDENTITY_LABEL, &[7; 32])
        );

        s.set_on(true);
        let on = s.blob_keys("user:1", &fill(9), 3).unwrap();
        assert_eq!((on.key_version, *on.identity), (1, *off.identity));
        let seal = on.seal.unwrap();
        assert_eq!(*seal, blake3::derive_key(BLOB_SEAL_LABEL, &[7; 32]));
        // Distinct from each other and from the subject key that seals values.
        assert_ne!(*seal, *on.identity);
        assert_ne!(*seal, [7; 32]);
        assert_ne!(*on.identity, [7; 32]);

        let access = s.blob_key_access();
        assert_eq!(*found(access.identity_key("user:1", 1)), *off.identity);
        assert_eq!(*found(access.seal_key("user:1", 1)), *seal);
        // Exact versions only, never created.
        assert!(matches!(access.seal_key("user:1", 2), KeyAnswer::Missing));
        assert!(matches!(access.seal_key("user:2", 1), KeyAnswer::Missing));
        assert!(matches!(access.seal_key("user 1", 1), KeyAnswer::Missing));
        assert_eq!(s.keystore().unwrap().stats().unwrap().keys, 1);
        assert!(matches!(
            s.blob_keys("user 1", &fill(1), 0),
            Err(PrivacyError::InvalidSubject(_))
        ));
    }

    #[test]
    fn blobs_keep_the_oldest_live_version_until_it_is_erased() {
        let s = sealer();
        s.set_on(true);
        // A value sealed first creates version 1; blobs use it too.
        let mut value = pb::Sealable::new_plain(Some("user:1".into()), b"x");
        s.seal_value(&mut value, &fill(3), 1).unwrap();
        let first = s.blob_keys("user:1", &fill(4), 2).unwrap();
        assert_eq!(first.key_version, 1);
        // A newer version seals values from now on; blobs keep version 1, so
        // equal content keeps its identity.
        let ks = s.keystore().unwrap();
        assert_eq!(ks.rotate("user:1", [5; 32], [5; 24], 3).unwrap(), 2);
        let still = s.blob_keys("user:1", &fill(6), 4).unwrap();
        assert_eq!((still.key_version, *still.identity), (1, *first.identity));
        // After an erasure every old version reads as erased, and the
        // subject's next blob gets a key numbered after them.
        assert_eq!(s.erase("user:1", 5).unwrap(), 2);
        let access = s.blob_key_access();
        assert!(matches!(access.seal_key("user:1", 1), KeyAnswer::Erased));
        assert!(matches!(
            access.identity_key("user:1", 2),
            KeyAnswer::Erased
        ));
        let after = s.blob_keys("user:1", &fill(7), 6).unwrap();
        assert_eq!(after.key_version, 3);
        assert_ne!(*after.identity, *first.identity);
    }

    /// Forks look keys up without creating them.
    #[test]
    fn existing_blob_keys_never_create_a_key() {
        let s = sealer();
        assert!(s.existing_blob_keys("user:3").unwrap().is_none());
        assert_eq!(s.keystore().unwrap().stats().unwrap().keys, 0);
        let made = s.blob_keys("user:3", &fill(4), 1).unwrap();
        let found = s.existing_blob_keys("user:3").unwrap().unwrap();
        assert_eq!(
            (found.key_version, *found.identity),
            (made.key_version, *made.identity)
        );
        assert_eq!(s.keystore().unwrap().stats().unwrap().keys, 1);
        s.erase("user:3", 2).unwrap();
        assert!(s.existing_blob_keys("user:3").unwrap().is_none());
    }

    #[test]
    fn a_restored_keystore_opens_the_same_blobs() {
        let s = sealer();
        s.set_on(true);
        let keys = s.blob_keys("user:9", &fill(2), 1).unwrap();
        let backup = s.keystore().unwrap().export_backup([1; 24]).unwrap();
        let (_dir, _restore, restored) =
            crate::keystore::staged_backup(&master(), &backup).unwrap();
        let restored = Sealer::new(restored);
        let access = restored.blob_key_access();
        assert_eq!(
            *found(access.identity_key("user:9", keys.key_version)),
            *keys.identity
        );
        assert_eq!(
            *found(access.seal_key("user:9", keys.key_version)),
            *keys.seal.unwrap()
        );
    }

    #[test]
    fn without_a_keystore_a_fixed_test_key_names_blobs() {
        let s = Sealer::plain();
        s.set_on(true);
        let k = s.blob_keys("user:1", &fill(1), 0).unwrap();
        assert_eq!(k.key_version, 1);
        assert!(k.seal.is_none());
        assert_eq!(
            *found(s.blob_key_access().identity_key("user:1", 1)),
            *k.identity
        );
        let other = Sealer::plain().blob_keys("user:2", &fill(1), 0).unwrap();
        assert_ne!(*other.identity, *k.identity);
        assert!(matches!(
            s.blob_key_access().identity_key("user:1", 2),
            KeyAnswer::Missing
        ));
    }
}
