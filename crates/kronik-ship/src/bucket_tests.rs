//! The root phase's local bucket reader (`Bucket::local`): what a bucket that
//! another user owns may hold in place of an object, and what is read.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

use super::{Bucket, ShipError};

/// A bucket directory under `/var/tmp`, whose ancestors only root controls
/// (`/var/tmp` is sticky), with `wrapped/current.wrapped`, two keystore
/// backups and a name in `keystore` that is no backup.
fn bucket() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("kronik-bucket-")
        .tempdir_in("/var/tmp")
        .unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    for sub in ["wrapped", "keystore"] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
    }
    std::fs::write(
        dir.path().join("wrapped/current.wrapped"),
        b"{\"wrapped\":1}",
    )
    .unwrap();
    std::fs::write(dir.path().join("keystore/10.bin"), b"older").unwrap();
    std::fs::write(dir.path().join("keystore/20.bin"), b"newer").unwrap();
    std::fs::create_dir(dir.path().join("keystore/not-a-backup")).unwrap();
    dir
}

fn local(path: &Path) -> Bucket<'static> {
    Bucket::local(path).unwrap()
}

const MAX: u64 = 1 << 20;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

#[test]
fn objects_and_listings_of_a_local_bucket_are_read_by_descriptor() {
    let dir = bucket();
    let bucket = local(dir.path());
    let rt = runtime();
    assert_eq!(
        rt.block_on(bucket.get("wrapped/current.wrapped", MAX))
            .unwrap(),
        Some(b"{\"wrapped\":1}".to_vec())
    );
    let mut names = rt.block_on(bucket.list("keystore")).unwrap();
    names.sort();
    // Files only: the directory in `keystore` is no object.
    assert_eq!(names, ["10.bin", "20.bin"]);
    // What is missing is missing, not an error: a directory, an object.
    assert_eq!(
        rt.block_on(bucket.get("keystore/30.bin", MAX)).unwrap(),
        None
    );
    assert_eq!(rt.block_on(bucket.get("nowhere/x.bin", MAX)).unwrap(), None);
    // An object larger than the bound is refused, not read into memory.
    assert!(rt.block_on(bucket.get("keystore/20.bin", 2)).is_err());
    assert!(rt.block_on(bucket.list("nowhere")).unwrap().is_empty());
}

/// A link to a file of the host in place of an object, a FIFO (which would
/// hang a reader that opens it), a second link to a file and a linked
/// directory are refused, and the file a link names is not read.
#[test]
fn a_link_a_fifo_or_a_linked_directory_in_the_bucket_is_refused_without_blocking() {
    let dir = bucket();
    let secret = dir.path().join("root-only");
    std::fs::write(&secret, b"never read").unwrap();
    let rt = runtime();
    let object = dir.path().join("keystore/20.bin");
    std::fs::remove_file(&object).unwrap();
    symlink(&secret, &object).unwrap();
    let refused = rt.block_on(local(dir.path()).get("keystore/20.bin", MAX));
    assert!(
        matches!(refused, Err(ShipError::Restore(ref m)) if m.contains("symbolic link")),
        "{refused:?}"
    );
    std::fs::remove_file(&object).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(&object)
        .status()
        .unwrap();
    assert!(made.success());
    let refused = rt.block_on(local(dir.path()).get("keystore/20.bin", MAX));
    assert!(matches!(refused, Err(ShipError::Restore(_))), "{refused:?}");
    std::fs::remove_file(&object).unwrap();
    std::fs::hard_link(&secret, &object).unwrap();
    let refused = rt.block_on(local(dir.path()).get("keystore/20.bin", MAX));
    assert!(
        matches!(refused, Err(ShipError::Restore(ref m)) if m.contains("hard links")),
        "{refused:?}"
    );
    // A linked directory is not followed, for an object nor for a listing.
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("current.wrapped"), b"planted").unwrap();
    std::fs::remove_dir_all(dir.path().join("wrapped")).unwrap();
    symlink(&elsewhere, dir.path().join("wrapped")).unwrap();
    let refused = rt.block_on(local(dir.path()).get("wrapped/current.wrapped", MAX));
    assert!(matches!(refused, Err(ShipError::Restore(_))), "{refused:?}");
    std::fs::remove_dir_all(dir.path().join("keystore")).unwrap();
    symlink(&elsewhere, dir.path().join("keystore")).unwrap();
    assert!(rt.block_on(local(dir.path()).list("keystore")).is_err());
}

/// The bucket itself is reached without following a link and is never made.
#[test]
fn the_bucket_is_reached_without_a_link_and_never_created() {
    let dir = bucket();
    let link = dir.path().with_extension("link");
    symlink(dir.path(), &link).unwrap();
    assert!(Bucket::local(&link).is_err());
    std::fs::remove_file(&link).unwrap();
    let missing = dir.path().join("missing");
    assert!(Bucket::local(&missing).is_err());
    assert!(!missing.exists());
    // A bucket below another user's directory is reached, as a nonroot
    // installation's /var/lib/kronik-ship/<name> is: by descriptor, no link.
    let nested = dir.path().join("wrapped");
    assert!(Bucket::local(&nested).is_ok());
}
