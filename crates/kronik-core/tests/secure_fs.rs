#![cfg(feature = "real")]
#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use bytes::Bytes;
use kronik_core::env::Env;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(5);

struct PrivateDirectory(std::path::PathBuf);

impl PrivateDirectory {
    fn new(env: &Env) -> Self {
        let mut random = [0; 16];
        env.entropy.fill(&mut random);
        let path =
            std::env::temp_dir().join(format!("kronik-secure-{:x}", u128::from_le_bytes(random)));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn secure_read_requires_private_owned_regular_single_link_nofollow_and_bound() {
    use std::io::Write as _;
    let env = Env::real(tokio::runtime::Handle::current());
    let dir = PrivateDirectory::new(&env);
    let path = dir.0.join("key");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"private").unwrap();
    assert_eq!(
        env.fs.read_secure(path.clone(), 7).await.unwrap(),
        b"private"
    );
    assert!(env.fs.read_secure(path.clone(), 6).await.is_err());
    assert!(env.fs.read_secure(path.clone(), 0).await.is_err());
    for mode in [0o640, 0o604, 0o610, 0o601] {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert!(env.fs.read_secure(path.clone(), 7).await.is_err());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let alias = dir.0.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(env.fs.read_secure(path.clone(), 7).await.is_err());
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(env.fs.read_secure(alias.clone(), 7).await.is_err());
    std::fs::remove_file(&alias).unwrap();
    let child = dir.0.join("child");
    std::fs::create_dir(&child).unwrap();
    std::os::unix::fs::symlink(&dir.0, child.join("parent")).unwrap();
    assert!(
        env.fs
            .read_secure(child.join("parent/key"), 7)
            .await
            .is_err()
    );
    assert!(env.fs.read_secure(child, 7).await.is_err());
    assert!(env.fs.read_secure(dir.0.join("missing"), 7).await.is_err());
    assert!(env.fs.read_secure(dir.0.join("../key"), 7).await.is_err());
    let fifo = dir.0.join("fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    assert!(
        tokio::time::timeout(DEADLINE, env.fs.read_secure(fifo, 7))
            .await
            .unwrap()
            .is_err()
    );
    if rustix::process::geteuid().is_root() {
        rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(1)), None).unwrap();
        assert!(env.fs.read_secure(path, 7).await.is_err());
    }
    let empty = dir.0.join("empty");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&empty)
        .unwrap();
    assert!(env.fs.read_secure(empty, 0).await.unwrap().is_empty());
}

#[tokio::test]
async fn secure_write_atomically_replaces_and_refuses_insecure_custody_without_damage() {
    use std::os::unix::fs::MetadataExt as _;
    let env = Env::real(tokio::runtime::Handle::current());
    let dir = PrivateDirectory::new(&env);
    let path = dir.0.join("token");
    env.fs
        .write_secure(path.clone(), b"first".to_vec())
        .await
        .unwrap();
    let first = std::fs::metadata(&path).unwrap();
    assert_eq!(first.mode() & 0o777, 0o600);
    assert_eq!(first.uid(), rustix::process::geteuid().as_raw());
    env.fs
        .write_secure(path.clone(), b"second".to_vec())
        .await
        .unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), first.ino());
    assert_eq!(
        env.fs.read_secure(path.clone(), 6).await.unwrap(),
        b"second"
    );

    // An unrelated crash leftover neither blocks this write nor gets replaced.
    let temporary = dir.0.join(".token.tmp");
    std::fs::write(&temporary, b"leftover").unwrap();
    let previous_inode = std::fs::metadata(&path).unwrap().ino();
    env.fs
        .write_secure(path.clone(), b"newer".to_vec())
        .await
        .unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), previous_inode);
    assert_eq!(std::fs::read(&temporary).unwrap(), b"leftover");
    assert_eq!(env.fs.read_secure(path.clone(), 5).await.unwrap(), b"newer");
    std::fs::remove_file(&temporary).unwrap();

    let alias = dir.0.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        env.fs
            .write_secure(path.clone(), b"lost".to_vec())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&alias).unwrap(), b"newer");
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(
        env.fs
            .write_secure(alias.clone(), b"lost".to_vec())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"newer");
    std::fs::remove_file(&alias).unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        env.fs
            .write_secure(path.clone(), b"lost".to_vec())
            .await
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        env.fs
            .write_secure(path.clone(), b"lost".to_vec())
            .await
            .is_err()
    );
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&alias).unwrap();
    assert!(
        env.fs
            .write_secure(alias.clone(), b"lost".to_vec())
            .await
            .is_err()
    );
    std::fs::remove_dir(&alias).unwrap();
    std::os::unix::fs::symlink(&dir.0, &alias).unwrap();
    assert!(
        env.fs
            .write_secure(alias.join("token"), b"lost".to_vec())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"newer");
    if rustix::process::geteuid().is_root() {
        let file = std::fs::File::open(&path).unwrap();
        rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(1)), None).unwrap();
        assert!(env.fs.write_secure(path, b"lost".to_vec()).await.is_err());
    }
}

#[tokio::test]
async fn secure_exclusive_write_creates_only_private_leaf_directory_and_never_replaces() {
    use std::os::unix::fs::MetadataExt as _;
    let env = Env::real(tokio::runtime::Handle::current());
    let dir = PrivateDirectory::new(&env);
    let keys = dir.0.join("keys");
    std::fs::create_dir(&keys).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = keys.join("fleet/key");
    env.fs
        .write_secure_new(path.clone(), Bytes::from_static(b"key"))
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&keys).unwrap().mode() & 0o777, 0o755);
    assert_eq!(
        std::fs::metadata(keys.join("fleet")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let inode = std::fs::metadata(&path).unwrap().ino();
    let error = env
        .fs
        .write_secure_new(path.clone(), Bytes::from_static(b"changed"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(env.fs.read_secure(path.clone(), 3).await.unwrap(), b"key");
    let alias = keys.join("fleet/alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert_eq!(
        env.fs
            .write_secure_new(alias, Bytes::from_static(b"changed"))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(
        env.fs
            .write_secure_new(keys.join("missing/intermediate/key"), Bytes::new())
            .await
            .is_err()
    );
    let replacement = keys.join("second/token");
    env.fs
        .write_secure(replacement.clone(), b"token".to_vec())
        .await
        .unwrap();
    assert_eq!(env.fs.read_secure(replacement, 5).await.unwrap(), b"token");
    let temporary = keys.join("fleet/.fresh.tmp");
    std::fs::write(&temporary, b"leftover").unwrap();
    env.fs
        .write_secure_new(keys.join("fleet/fresh"), Bytes::from_static(b"new"))
        .await
        .unwrap();
    assert_eq!(
        env.fs
            .read_secure(keys.join("fleet/fresh"), 3)
            .await
            .unwrap(),
        b"new"
    );
    assert_eq!(std::fs::read(temporary).unwrap(), b"leftover");
}

#[tokio::test]
async fn secure_exclusive_racing_writers_publish_one_complete_private_payload() {
    use std::os::unix::fs::MetadataExt as _;
    let env = Env::real(tokio::runtime::Handle::current());
    let dir = PrivateDirectory::new(&env);
    let path = dir.0.join("race/token");
    let (first, second) = tokio::join!(
        env.fs
            .write_secure_new(path.clone(), Bytes::from_static(b"first")),
        env.fs
            .write_secure_new(path.clone(), Bytes::from_static(b"second")),
    );
    let expected = match (first, second) {
        (Ok(()), Err(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            b"first".as_slice()
        }
        (Err(error), Ok(())) => {
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            b"second".as_slice()
        }
        result => panic!("exactly one exclusive writer must commit: {result:?}"),
    };
    assert_eq!(env.fs.read_secure(path.clone(), 6).await.unwrap(), expected);
    let metadata = std::fs::metadata(path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(std::fs::read_dir(dir.0.join("race")).unwrap().count(), 1);
}
