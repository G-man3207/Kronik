//! The existing exclusive directory lock, retained without reacquiring it.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use rustix::fs::{Mode, OFlags};

use crate::PrivacyError;
use crate::publication::DataPublisher;

#[derive(Clone)]
pub struct DataOwnership(Arc<OwnedDirectory>);

struct OwnedDirectory {
    file: Arc<File>,
    path: PathBuf,
    publisher: Arc<DataPublisher>,
    // Routing only; all pending/current facts remain in the original runtime DATA state.
    secret_store: Mutex<Weak<crate::SecretStoreOwner>>,
}

impl std::fmt::Debug for DataOwnership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataOwnership(..)")
    }
}

impl DataOwnership {
    // Only lock_data can mint this after locking and checking the actual File.
    pub(super) fn locked(file: File, path: PathBuf) -> Self {
        Self(Arc::new(OwnedDirectory {
            file: Arc::new(file),
            path,
            publisher: Arc::new(DataPublisher::default()),
            secret_store: Mutex::new(Weak::new()),
        }))
    }

    /// The SAME original resource used by the existing node lifecycle/writer.
    pub fn directory_resource(&self) -> &Arc<File> {
        &self.0.file
    }

    pub(crate) fn publisher(&self) -> &Arc<DataPublisher> {
        &self.0.publisher
    }

    pub(crate) fn secret_store_route(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Weak<crate::SecretStoreOwner>>, PrivacyError> {
        self.0
            .secret_store
            .lock()
            .map_err(|_| PrivacyError::SecretStoreUnknown)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }

    pub fn begin_keystore_restore(&self) -> Result<crate::keystore::KeystoreRestore, PrivacyError> {
        crate::keystore::KeystoreRestore::begin(self)
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn check_location(&self) -> Result<(), PrivacyError> {
        let held = self.0.file.metadata().map_err(|source| self.io(source))?;
        let named = std::fs::metadata(&self.0.path).map_err(|source| self.io(source))?;
        if !held.is_dir() || (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(crate::PublicationError::FileIdentity(
                "the original owned root directory was replaced",
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn check_directory(&self, relative: &Path, held: &File) -> Result<(), PrivacyError> {
        let current = self.directory(relative, false)?;
        let current = current.metadata().map_err(|source| self.io(source))?;
        let held = held.metadata().map_err(|source| self.io(source))?;
        if (current.dev(), current.ino()) != (held.dev(), held.ino()) {
            return Err(crate::PublicationError::FileIdentity(
                "the held keystore directory was replaced",
            )
            .into());
        }
        Ok(())
    }

    /// Walk from the held root, never through a caller-supplied directory File.
    pub(crate) fn directory(
        &self,
        relative: &Path,
        create: bool,
    ) -> Result<Arc<File>, PrivacyError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut parent = self.0.file.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(PrivacyError::InvalidName(
                    "keystore location must stay beneath the owned root".into(),
                ));
            };
            let child = match rustix::fs::openat(parent.as_ref(), name, flags, Mode::empty()) {
                Err(rustix::io::Errno::NOENT) if create => {
                    match rustix::fs::mkdirat(
                        parent.as_ref(),
                        name,
                        Mode::RUSR | Mode::WUSR | Mode::XUSR,
                    ) {
                        Ok(()) => rustix::fs::fsync(parent.as_ref())
                            .map_err(|source| self.io(source.into()))?,
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(source) => return Err(self.io(source.into())),
                    }
                    rustix::fs::openat(parent.as_ref(), name, flags, Mode::empty())
                }
                result => result,
            }
            .map_err(|source| self.io(source.into()))?;
            parent = Arc::new(File::from(child));
        }
        Ok(parent)
    }

    pub(crate) fn io(&self, source: std::io::Error) -> PrivacyError {
        PrivacyError::CustodyIo {
            path: self.0.path.display().to_string(),
            source,
        }
    }
}
