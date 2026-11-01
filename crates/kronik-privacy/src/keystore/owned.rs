//! Mutable file custody is attached only by the canonical owned-root factory.
//! Compliant mutable processes retain the existing exclusive directory owner;
//! independent managed handles reuse it. External raw SQL corruption remains
//! covered by pre/post SQL checks, not by this process-local final-move fence.
//! Filesystem promotion preserves the offline restore contract: managed SQLite
//! handles close before rename; in-place restore_owned supports live handles.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags};
use rustix::fs::{AtFlags, FileType};

use super::Keystore;
use super::ffi::{FileIdentity, file_identity};
use crate::key_source::DataOwnership;
use crate::publication::{DataPublisher, KeystoreMutation};
use crate::{MasterKey, PrivacyError, PublicationError};

pub(super) enum Custody {
    Memory(Arc<DataPublisher>),
    Owned(Arc<OwnedStore>),
    ReadOnly,
}

pub(super) struct OwnedStore {
    pub owner: DataOwnership,
    pub relative: PathBuf,
    pub directory: Arc<File>,
    pub identity: FileIdentity,
    pub live: bool,
    pub stage: Option<u64>,
}

impl Custody {
    pub(super) fn readonly(&self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    pub(super) fn publisher(&self) -> Result<&Arc<DataPublisher>, PublicationError> {
        match self {
            Self::Memory(publisher) => Ok(publisher),
            Self::Owned(store) => Ok(store.owner.publisher()),
            Self::ReadOnly => Err(PublicationError::Unowned),
        }
    }

    pub(super) fn live_identity(&self) -> Option<(u64, u64)> {
        match self {
            Self::Owned(store) if store.live => Some((store.identity.device, store.identity.inode)),
            _ => None,
        }
    }

    pub(super) fn stage(&self) -> Option<u64> {
        if let Self::Owned(store) = self {
            store.stage
        } else {
            None
        }
    }

    pub(super) fn require_mutable(&self) -> Result<(), PrivacyError> {
        self.publisher()?
            .check_mutable(self.stage())
            .map_err(Into::into)
    }

    pub(super) fn check(&self) -> Result<(), PrivacyError> {
        if let Self::Owned(store) = self {
            store.check()?;
        }
        Ok(())
    }
}

impl OwnedStore {
    fn open(
        owner: &DataOwnership,
        relative: &Path,
        live: bool,
        stage: Option<u64>,
        create: bool,
    ) -> Result<(Mutex<Connection>, Arc<Self>), PrivacyError> {
        let directory = owner.directory(relative, create)?;
        owner.check_location()?;
        // The name locates the connection, never proves its identity. FILESTAT
        // below obtains the actual SQLite-opened descriptor, then fstatat joins
        // it to the SAME held root-relative directory without opening a DB fd.
        let filename = owner.path().join(relative).join("keystore.db");
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let conn = Mutex::new(Connection::open_with_flags(filename, flags)?);
        let identity = {
            let guard = conn.lock().map_err(|_| PublicationError::Uncertified)?;
            file_identity(&guard)?
        };
        let store = Arc::new(Self {
            owner: owner.clone(),
            relative: relative.to_owned(),
            directory,
            identity,
            live,
            stage,
        });
        store.check()?;
        Ok((conn, store))
    }

    fn check(&self) -> Result<(), PrivacyError> {
        self.owner.check_location()?;
        self.owner
            .check_directory(&self.relative, &self.directory)?;
        let named = rustix::fs::statat(
            self.directory.as_ref(),
            "keystore.db",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|source| self.owner.io(source.into()))?;
        if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
            || named.st_dev as u64 != self.identity.device
            || named.st_ino as u64 != self.identity.inode
        {
            return Err(PublicationError::FileIdentity(
                "the opened keystore no longer matches its held directory entry",
            )
            .into());
        }
        Ok(())
    }
}

impl Keystore {
    /// The actual exclusive root owner is mandatory for a mutable file store.
    pub fn open_owned(
        owner: &DataOwnership,
        master: &MasterKey,
    ) -> Result<Arc<Self>, PrivacyError> {
        let (conn, store) = OwnedStore::open(owner, Path::new("keys"), true, None, true)?;
        owner
            .publisher()
            .select_initial((store.identity.device, store.identity.inode))?;
        Self::open_connection(conn, master, Custody::Owned(store)).map(Arc::new)
    }

    /// The retained original DATA owner for an existing owned restore; never authority.
    pub fn data_ownership(&self) -> Result<&DataOwnership, PrivacyError> {
        let Custody::Owned(store) = &self.custody else {
            return Err(PublicationError::Unowned.into());
        };
        store.check()?;
        Ok(&store.owner)
    }

    /// A second connection explicitly reuses the SAME owner and publisher.
    pub fn reopen_owned(&self) -> Result<Arc<Self>, PrivacyError> {
        let Custody::Owned(original) = &self.custody else {
            return Err(PublicationError::Unowned.into());
        };
        let (conn, store) = OwnedStore::open(
            &original.owner,
            &original.relative,
            original.live,
            original.stage,
            false,
        )?;
        if store.identity != original.identity {
            return Err(
                PublicationError::FileIdentity("the original owned keystore was replaced").into(),
            );
        }
        self.reopen_connection(conn, Custody::Owned(original.clone()))
            .map(Arc::new)
    }

    /// Genuinely private memory custody; it is not a file-owner certificate.
    pub fn open_memory(master: &MasterKey) -> Result<Self, PrivacyError> {
        Self::open_connection(
            Mutex::new(Connection::open_in_memory()?),
            master,
            Custody::Memory(Arc::new(DataPublisher::default())),
        )
    }

    /// A frozen/offline reader cannot create schema, keys or mutation authority.
    pub fn open_readonly(conn: Connection, master: &MasterKey) -> Result<Self, PrivacyError> {
        if !conn.is_readonly("main")? {
            return Err(PublicationError::Unowned.into());
        }
        Self::open_connection(Mutex::new(conn), master, Custody::ReadOnly)
    }

    pub fn erasure_revision(&self) -> Result<u64, PrivacyError> {
        self.custody
            .publisher()?
            .revision_for(self.custody.live_identity(), self.custody.stage())
            .map_err(Into::into)
    }

    /// Final publication is a bounded move under the same original caller's
    /// admission. No SQL, filesystem work, await or retirement belongs here.
    pub fn with_erasure_revision<T>(
        &self,
        expected: u64,
        publish: impl FnOnce() -> T,
    ) -> Result<Option<T>, PrivacyError> {
        self.custody
            .publisher()?
            .publish_for(
                expected,
                self.custody.live_identity(),
                self.custody.stage(),
                publish,
            )
            .map_err(Into::into)
    }

    pub(super) fn begin_erasure(&self) -> Result<KeystoreMutation, PrivacyError> {
        self.custody
            .publisher()?
            .begin_for(self.custody.stage())
            .map_err(Into::into)
    }

    pub fn restore_owned(
        owner: &DataOwnership,
        master: &MasterKey,
        backup: &[u8],
    ) -> Result<Arc<Self>, PrivacyError> {
        let rows = Self::read_backup(master, backup)?;
        let mutation = owner.publisher().begin()?;
        let (conn, store) = OwnedStore::open(owner, Path::new("keys"), true, None, true)?;
        {
            let mut connection = conn.lock().map_err(|_| PublicationError::Uncertified)?;
            Self::replace_backup(&mut connection, master, &rows)?;
        }
        let result = Self::open_connection(conn, master, Custody::Owned(store.clone()))?;
        mutation.finish_selected((store.identity.device, store.identity.inode))?;
        Ok(Arc::new(result))
    }

    /// Import belongs to the SAME already-started restore phase. It does not
    /// certify the live root before its caller's durable filesystem install.
    pub fn restore_staged(
        restore: &KeystoreRestore,
        relative_stage: &Path,
        master: &MasterKey,
        backup: &[u8],
    ) -> Result<Arc<Self>, PrivacyError> {
        if relative_stage.as_os_str().is_empty() || relative_stage == Path::new("keys") {
            return Err(PublicationError::FileIdentity(
                "a restore stage is distinct from the live keys directory",
            )
            .into());
        }
        {
            let mut stage = restore
                .stage
                .lock()
                .map_err(|_| PublicationError::Uncertified)?;
            if !matches!(*stage, Stage::Empty) {
                return Err(PublicationError::Busy.into());
            }
            *stage = Stage::Opening;
        }
        let rows = Self::read_backup(master, backup)?;
        let (conn, store) = OwnedStore::open(
            &restore.owner,
            relative_stage,
            false,
            Some(restore.mutation.id()),
            true,
        )?;
        {
            let mut connection = conn.lock().map_err(|_| PublicationError::Uncertified)?;
            Self::replace_backup(&mut connection, master, &rows)?;
        }
        let keys = Self::open_connection(conn, master, Custody::Owned(store.clone()))?;
        let mut stage = restore
            .stage
            .lock()
            .map_err(|_| PublicationError::Uncertified)?;
        *stage = Stage::Ready {
            identity: store.identity,
            directory: store.directory.clone(),
            closed: false,
        };
        drop(stage);
        Ok(Arc::new(keys))
    }

    pub fn restore_memory(master: &MasterKey, backup: &[u8]) -> Result<Self, PrivacyError> {
        let rows = Self::read_backup(master, backup)?;
        let conn = Mutex::new(Connection::open_in_memory()?);
        {
            let mut connection = conn.lock().map_err(|_| PublicationError::Uncertified)?;
            Self::replace_backup(&mut connection, master, &rows)?;
        }
        Self::open_connection(
            conn,
            master,
            Custody::Memory(Arc::new(DataPublisher::default())),
        )
    }
}

enum Stage {
    Empty,
    Opening,
    Ready {
        identity: FileIdentity,
        directory: Arc<File>,
        closed: bool,
    },
}

/// The original restore's DATA phase, spanning staging and ALL real install
/// I/O without retaining a publication lock or inventing a source/role grant.
pub struct KeystoreRestore {
    owner: DataOwnership,
    mutation: KeystoreMutation,
    stage: std::sync::Mutex<Stage>,
}

impl KeystoreRestore {
    pub(crate) fn begin(owner: &DataOwnership) -> Result<Self, PrivacyError> {
        Ok(Self {
            owner: owner.clone(),
            mutation: owner.publisher().begin_stage()?,
            stage: std::sync::Mutex::new(Stage::Empty),
        })
    }

    /// Call before renaming SQLite files. Closing the managed connection after
    /// checkpoint is the existing restore contract; no extra DB fd is closed.
    pub fn close_stage(&self, keys: Arc<Keystore>) -> Result<(), PrivacyError> {
        let keys = Arc::try_unwrap(keys).map_err(|_| PublicationError::Busy)?;
        let Custody::Owned(store) = &keys.custody else {
            return Err(PublicationError::Unowned.into());
        };
        if store.stage != Some(self.mutation.id()) || !store.owner.same_owner(&self.owner) {
            return Err(PublicationError::Unowned.into());
        }
        if Arc::strong_count(store) != 1 {
            return Err(PublicationError::Busy.into());
        }
        let expected = {
            let stage = self
                .stage
                .lock()
                .map_err(|_| PublicationError::Uncertified)?;
            match &*stage {
                Stage::Ready {
                    identity,
                    closed: false,
                    ..
                } => *identity,
                _ => return Err(PublicationError::Uncertified.into()),
            }
        };
        if store.identity != expected {
            return Err(PublicationError::Unowned.into());
        }
        {
            let conn = keys.checked_conn()?;
            let busy: i64 =
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            if busy != 0 {
                return Err(PublicationError::Busy.into());
            }
        }
        drop(keys);
        let mut stage = self
            .stage
            .lock()
            .map_err(|_| PublicationError::Uncertified)?;
        if let Stage::Ready { closed, .. } = &mut *stage {
            *closed = true;
        }
        Ok(())
    }

    /// Invoke only after the actual restore transaction's durable installed
    /// marker/fsync. Some(master) requires the original staged inode at LIVE;
    /// None is valid only when this restore did not import a keystore.
    pub fn finish(self, master: Option<&MasterKey>) -> Result<Option<Arc<Keystore>>, PrivacyError> {
        let stage = self
            .stage
            .into_inner()
            .map_err(|_| PublicationError::Uncertified)?;
        match (stage, master) {
            (Stage::Empty, None) => {
                self.mutation.finish()?;
                Ok(None)
            }
            (
                Stage::Ready {
                    identity,
                    directory,
                    closed: true,
                },
                Some(master),
            ) => {
                let (conn, live) =
                    OwnedStore::open(&self.owner, Path::new("keys"), true, None, false)?;
                if live.identity != identity {
                    return Err(PublicationError::FileIdentity(
                        "installed live keystore is not the original staged file",
                    )
                    .into());
                }
                let keys = Keystore::open_connection(conn, master, Custody::Owned(live.clone()))?;
                self.mutation
                    .finish_selected((live.identity.device, live.identity.inode))?;
                drop(directory);
                Ok(Some(Arc::new(keys)))
            }
            _ => Err(PublicationError::Uncertified.into()),
        }
    }
}
