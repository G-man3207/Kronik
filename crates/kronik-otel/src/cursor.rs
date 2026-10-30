//! The export cursors, `<data>/export.json` (m28-otel §4.6, ADR 0084).
//! A manifest selects acknowledged positions and resume state. Every replacement
//! uses a fresh inode, file fsync, rename and directory fsync before publication.

use std::collections::BTreeMap;
use std::io;
use std::ops::Bound::{Excluded, Unbounded};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bytes::Bytes;
use kronik_core::env::{Env, OpenMode};
use kronik_core::ids::Lsn;
use serde::{Deserialize, Serialize};

/// Delivery identity; zero is the legacy generation, before any rewind.
pub type Generation = [u8; 16];

/// A durable rewind intent, retained until replay reaches the old head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewind {
    pub generation: Generation,
    pub to: Lsn,
    pub through: Lsn,
}

/// Versioned delivery control, independent of the sink's opaque resume state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ControlWire")]
pub struct Control {
    pub version: u8,
    /// Generation whose state and LSN have actually been checkpointed.
    pub generation: Generation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewind: Option<Rewind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlWire {
    version: u8,
    generation: Generation,
    #[serde(default)]
    rewind: Option<Rewind>,
}

impl Control {
    pub const VERSION: u8 = 1;

    pub fn new(generation: Generation) -> Self {
        Self {
            version: Self::VERSION,
            generation,
            rewind: None,
        }
    }

    fn validate(self) -> Result<(), &'static str> {
        if self.version != Self::VERSION {
            return Err("unsupported export control version");
        }
        if let Some(rewind) = self.rewind
            && (rewind.generation == [0; 16] || rewind.to > rewind.through)
        {
            return Err("invalid export rewind generation or range");
        }
        Ok(())
    }
}

impl TryFrom<ControlWire> for Control {
    type Error = &'static str;

    fn try_from(wire: ControlWire) -> Result<Self, Self::Error> {
        let control = Self {
            version: wire.version,
            generation: wire.generation,
            rewind: wire.rewind,
        };
        control.validate()?;
        Ok(control)
    }
}

/// One stream's position. Real legacy `{lsn,state}` entries remain readable.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// The last LSN delivered; the stream resumes after it.
    pub lsn: Lsn,
    /// The stream's own resume state (`null` for none).
    #[serde(default)]
    pub state: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<Control>,
}

impl Entry {
    pub fn generation(&self) -> Generation {
        self.control.map_or([0; 16], |control| control.generation)
    }

    pub fn pending_rewind(&self) -> Option<Rewind> {
        self.control.and_then(|control| control.rewind)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if let Some(control) = self.control {
            control.validate()?;
            if let Some(rewind) = control.rewind
                && rewind.to > self.lsn
            {
                return Err("export rewind cut exceeds acknowledged position");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Serialize)]
struct EntryRef<'a> {
    lsn: Lsn,
    state: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    control: Option<Control>,
}

impl<'a> From<&'a Entry> for EntryRef<'a> {
    fn from(entry: &'a Entry) -> Self {
        Self {
            lsn: entry.lsn,
            state: &entry.state,
            control: entry.control,
        }
    }
}

/// The cursor file, shared by every stream of one data directory.
pub struct Cursors {
    env: Env,
    path: PathBuf,
    entries: Mutex<BTreeMap<String, Entry>>,
    /// Serializes manifest replacement and read/merge/write control operations.
    write: tokio::sync::Mutex<()>,
    active: bool,
}

impl Cursors {
    pub const FILE: &'static str = "export.json";

    /// Reads `<data>/export.json`; a missing file is no cursors. An
    /// unreadable one is an error rather than a silent restart from 0.
    pub async fn load(env: Env, data_dir: &Path) -> io::Result<Cursors> {
        let path = data_dir.join(Self::FILE);
        let entries: BTreeMap<String, Entry> = if env.fs.exists(path.clone()).await? {
            let f = env.fs.open(path.clone(), OpenMode::Read).await?;
            let len = f.len().await?;
            if len > u64::from(kronik_log::MAX_RECORD) {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "export cursor manifest exceeds the log record byte budget",
                ));
            }
            let bytes = f
                .read_at(0, usize::try_from(len).unwrap_or(usize::MAX))
                .await?;
            serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?
        } else {
            BTreeMap::new()
        };
        for entry in entries.values() {
            entry
                .validate()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        Ok(Cursors {
            env,
            path,
            entries: Mutex::new(entries),
            write: tokio::sync::Mutex::new(()),
            active: true,
        })
    }

    /// Empty, read-only cursors when disabled exporters cannot read their file.
    /// The unknown file is never replaced, even by an accidental writer.
    pub fn inactive(env: Env, data_dir: &Path) -> Self {
        Self {
            env,
            path: data_dir.join(Self::FILE),
            entries: Mutex::new(BTreeMap::new()),
            write: tokio::sync::Mutex::new(()),
            active: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The stream's saved position, if it has one.
    pub fn get(&self, stream: &str) -> Option<Entry> {
        self.lock().get(stream).cloned()
    }

    /// Exact durable replacement for startup, configuration and restore.
    /// Followers use `advance` so concurrent rewind intents cannot be lost.
    pub async fn save(&self, stream: &str, entry: Entry) -> io::Result<()> {
        let _writer = self.write.lock().await;
        self.writable()?;
        entry.validate().map_err(invalid_input)?;
        let bytes = self.serialize(Some((stream, EntryRef::from(&entry))))?;
        self.replace(bytes).await?;
        self.publish(stream, entry);
        Ok(())
    }

    /// Durably reselects cached entries on a fresh inode before metadata files
    /// are reopened or reused after an indeterminate manifest replacement.
    pub async fn stabilize(&self) -> io::Result<()> {
        let _writer = self.write.lock().await;
        self.writable()?;
        self.replace(self.serialize(None)?).await
    }

    /// Persists intent without changing the applied generation or resume state.
    pub async fn request_rewind(
        &self,
        stream: &str,
        generation: Generation,
        to: Lsn,
    ) -> io::Result<Rewind> {
        let _writer = self.write.lock().await;
        self.writable()?;
        let (rewind, control, bytes) = {
            let entries = self.lock();
            let empty = Entry::default();
            let current = entries.get(stream).unwrap_or(&empty);
            if generation == [0; 16] || generation == current.generation() {
                return Err(invalid_input("rewind requires a new nonzero generation"));
            }
            if to > current.lsn {
                return Err(invalid_input("rewind cut exceeds durable cursor"));
            }
            let old = current.pending_rewind();
            let rewind = Rewind {
                generation,
                to: old.map_or(to, |old| old.to.min(to)),
                through: old.map_or(current.lsn, |old| old.through.max(current.lsn)),
            };
            let mut control = Control::new(current.generation());
            control.rewind = Some(rewind);
            let entry = EntryRef {
                control: Some(control),
                ..EntryRef::from(current)
            };
            (
                rewind,
                control,
                Self::serialize_entries(&entries, Some((stream, entry)))?,
            )
        };
        self.replace(bytes).await?;
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(stream) {
            entry.control = Some(control);
        } else {
            entries.insert(
                stream.to_owned(),
                Entry {
                    control: Some(control),
                    ..Entry::default()
                },
            );
        }
        Ok(rewind)
    }

    /// Saves a follower checkpoint, merging the latest durable rewind intent.
    /// A new generation may first be saved only at its pending cut. Old acks
    /// can extend the replay head, but cannot satisfy or erase the intent.
    pub async fn advance(&self, stream: &str, mut entry: Entry) -> io::Result<Entry> {
        let _writer = self.write.lock().await;
        self.writable()?;
        entry.validate().map_err(invalid_input)?;
        {
            let entries = self.lock();
            let empty = Entry::default();
            let current = entries.get(stream).unwrap_or(&empty);
            let generation = entry.generation();
            let mut pending = current.pending_rewind();
            if generation != current.generation() {
                if !pending
                    .is_some_and(|rewind| rewind.generation == generation && rewind.to == entry.lsn)
                {
                    return Err(invalid_input(
                        "stale export generation or checkpoint outside rewind cut",
                    ));
                }
            } else if entry.lsn < current.lsn {
                return Err(invalid_input("stale export checkpoint"));
            }
            if let Some(rewind) = &mut pending {
                if generation != rewind.generation {
                    rewind.through = rewind.through.max(entry.lsn);
                } else if entry.lsn >= rewind.through {
                    pending = None;
                }
            }
            if entry.control.is_some() || current.control.is_some() {
                let mut control = Control::new(generation);
                control.rewind = pending;
                entry.control = Some(control);
            }
        }
        let bytes = self.serialize(Some((stream, EntryRef::from(&entry))))?;
        self.replace(bytes).await?;
        self.publish(stream, entry.clone());
        Ok(entry)
    }

    fn publish(&self, stream: &str, entry: Entry) {
        let mut entries = self.lock();
        if let Some(current) = entries.get_mut(stream) {
            *current = entry;
        } else {
            entries.insert(stream.to_owned(), entry);
        }
    }

    fn writable(&self) -> io::Result<()> {
        if self.active {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "export cursors are inactive and read-only",
            ))
        }
    }

    fn serialize(&self, replacement: Option<(&str, EntryRef<'_>)>) -> io::Result<Vec<u8>> {
        Self::serialize_entries(&self.lock(), replacement)
    }

    fn serialize_entries(
        entries: &BTreeMap<String, Entry>,
        replacement: Option<(&str, EntryRef<'_>)>,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = crate::trace_state::LimitedVec::new(kronik_log::MAX_RECORD as usize);
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        if let Some((stream, entry)) = replacement {
            let before = entries.range::<str, _>((Unbounded, Excluded(stream)));
            let after = entries.range::<str, _>((Excluded(stream), Unbounded));
            let staged = before
                .map(|(name, entry)| (name.as_str(), EntryRef::from(entry)))
                .chain(std::iter::once((stream, entry)))
                .chain(after.map(|(name, entry)| (name.as_str(), EntryRef::from(entry))));
            serde::Serializer::collect_map(&mut serializer, staged).map_err(io::Error::from)?;
        } else {
            entries
                .serialize(&mut serializer)
                .map_err(io::Error::from)?;
        }
        Ok(bytes.into_vec())
    }

    async fn replace(&self, bytes: Vec<u8>) -> io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        // Unlink first: an indeterminate rename must never leave us modifying
        // an inode that may still be the manifest selected after a crash.
        match self.env.fs.remove_file(tmp.clone()).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let f = self
            .env
            .fs
            .open(tmp.clone(), OpenMode::ReadWriteCreate)
            .await?;
        f.set_len(0).await?;
        f.write_at(0, Bytes::from(bytes)).await?;
        f.sync_data().await?;
        self.env.fs.rename(tmp, self.path.clone()).await?;
        if let Some(dir) = self.path.parent() {
            self.env.fs.sync_dir(dir.to_owned()).await?;
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
