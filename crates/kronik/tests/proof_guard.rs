//! The guards of the bring-up helper and the boundary driver: the machine marker
//! (G1), the ids (G2), the flat-file allocations (G3), the space (G4) and the
//! runtime limit (G6). Both include the same file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/proof_guard.rs"]
mod proof_guard;

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

use proof_guard::*;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new(machine_id: &str) -> Host {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("machine-id"), machine_id).unwrap();
        Host { dir }
    }
    fn id(&self) -> std::path::PathBuf {
        self.dir.path().join("machine-id")
    }
    fn marker(&self) -> std::path::PathBuf {
        self.dir.path().join("marker")
    }
    fn write_marker(&self, text: &str, mode: u32) {
        fs::write(self.marker(), text).unwrap();
        fs::set_permissions(self.marker(), fs::Permissions::from_mode(mode)).unwrap();
    }
    fn check(&self) -> anyhow::Result<()> {
        require_proof_host(&self.marker(), &self.id(), me())
    }
}

fn message(result: anyhow::Result<()>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn g1_a_machine_without_the_marker_is_refused_with_the_command_that_writes_it() {
    let host = Host::new(&format!("{ID}\n"));
    let text = message(host.check());
    assert!(text.contains("does not exist"), "{text}");
    assert!(
        text.contains("cat /etc/machine-id > /etc/kronik-proof-host"),
        "{text}"
    );
    assert!(text.contains("transient service"), "{text}");
}

#[test]
fn g1_the_marker_must_hold_this_machines_id_and_be_a_plain_file_nobody_else_writes() {
    let host = Host::new(&format!("{ID}\n"));
    // The right content, with or without the newline, passes.
    host.write_marker(&format!("{ID}\n"), 0o644);
    host.check().unwrap();
    host.write_marker(ID, 0o600);
    host.check().unwrap();
    // Another machine's id.
    host.write_marker("ffffffffffffffffffffffffffffffff\n", 0o644);
    assert!(message(host.check()).contains("another machine's id"));
    // Empty, or not an id at all.
    host.write_marker("", 0o644);
    assert!(host.check().is_err());
    host.write_marker(&"x".repeat(4096), 0o644);
    assert!(message(host.check()).contains("not a machine id"));
    // Writable by the group or others: someone else could have written it.
    host.write_marker(ID, 0o664);
    assert!(message(host.check()).contains("nobody else can write"));
    host.write_marker(ID, 0o646);
    assert!(host.check().is_err());
    // Owned by somebody else than root.
    host.write_marker(ID, 0o644);
    assert!(require_proof_host(&host.marker(), &host.id(), me().wrapping_add(1)).is_err());
    // A link to a file with the right content is no marker.
    fs::remove_file(host.marker()).unwrap();
    fs::write(host.dir.path().join("real"), ID).unwrap();
    symlink(host.dir.path().join("real"), host.marker()).unwrap();
    assert!(message(host.check()).contains("regular file"));
    // A directory is no marker.
    fs::remove_file(host.marker()).unwrap();
    fs::create_dir(host.marker()).unwrap();
    assert!(host.check().is_err());
}

#[test]
fn g1_a_host_without_an_initialized_machine_id_cannot_be_told_from_another() {
    for id in [
        "uninitialized\n",
        "",
        "\n",
        "0123\n",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
    ] {
        let host = Host::new(id);
        host.write_marker(id, 0o644);
        let text = message(host.check());
        assert!(text.contains("initialized machine id"), "{id:?}: {text}");
    }
    // No machine-id file at all.
    let host = Host::new(ID);
    fs::remove_file(host.id()).unwrap();
    assert!(host.check().is_err());
}

fn fake_proc(processes: &[(&str, &str)]) -> tempfile::TempDir {
    let proc = tempfile::tempdir().unwrap();
    for (pid, status) in processes {
        fs::create_dir(proc.path().join(pid)).unwrap();
        fs::write(proc.path().join(pid).join("status"), status).unwrap();
    }
    // Entries that are not processes, and a process without a readable status.
    fs::create_dir(proc.path().join("sys")).unwrap();
    fs::write(proc.path().join("version"), "Linux").unwrap();
    fs::create_dir(proc.path().join("999")).unwrap();
    proc
}

const IDS: [(IdKind, u32); 3] = [
    (IdKind::User, 10_001),
    (IdKind::User, 10_002),
    (IdKind::Group, 10_003),
];

#[test]
fn g2_an_id_the_name_service_knows_is_refused_whatever_files_say() {
    let proc = fake_proc(&[("1", "Name:\tinit\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")]);
    let nobody = |_: IdKind, _: u32| Ok(false);
    require_unused_ids(&IDS, &nobody, proc.path()).unwrap();
    for (kind, id) in IDS {
        let knows = move |k: IdKind, i: u32| Ok(k == kind && i == id);
        let text = message(require_unused_ids(&IDS, &knows, proc.path()));
        assert!(
            text.contains(&format!("id {id}")) && text.contains("getent"),
            "{text}"
        );
    }
    // Asking can fail (no getent, a name service that does not answer): refused.
    let broken = |_: IdKind, _: u32| anyhow::bail!("no such program");
    let text = message(require_unused_ids(&IDS, &broken, proc.path()));
    assert!(text.contains("cannot be shown to be unused"), "{text}");
}

#[test]
fn g2_a_process_that_runs_as_a_chosen_id_in_any_of_its_four_ids_is_refused() {
    let nobody = |_: IdKind, _: u32| Ok(false);
    // Real, effective, saved and filesystem user id, and the same for groups.
    for status in [
        "Uid:\t10001\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
        "Uid:\t0\t10002\t0\t0\nGid:\t0\t0\t0\t0\n",
        "Uid:\t0\t0\t10001\t0\nGid:\t0\t0\t0\t0\n",
        "Uid:\t0\t0\t0\t10002\nGid:\t0\t0\t0\t0\n",
        "Uid:\t0\t0\t0\t0\nGid:\t10003\t0\t0\t0\n",
        "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t10003\n",
    ] {
        let proc = fake_proc(&[("1", "Uid:\t0\t0\t0\t0\n"), ("4242", status)]);
        let text = message(require_unused_ids(&IDS, &nobody, proc.path()));
        assert!(text.contains("process 4242"), "{status:?}: {text}");
    }
    // A user id that is the number of a chosen group (and the reverse) is not a clash.
    let proc = fake_proc(&[(
        "5",
        "Uid:\t10003\t10003\t10003\t10003\nGid:\t10001\t10001\t10001\t10001\n",
    )]);
    require_unused_ids(&IDS, &nobody, proc.path()).unwrap();
    // Nothing else running as them: fine.
    let proc = fake_proc(&[
        ("1", "Uid:\t0\t0\t0\t0\n"),
        ("2", "Uid:\t998\t998\t998\t998\n"),
    ]);
    require_unused_ids(&IDS, &nobody, proc.path()).unwrap();
    // This host: nothing runs as these numbers, and getent answers.
    let sound = |k: IdKind, i: u32| getent_knows(k, i);
    require_unused_ids(
        &[
            (IdKind::User, 3_999_999_001),
            (IdKind::Group, 3_999_999_002),
        ],
        &sound,
        Path::new("/proc"),
    )
    .unwrap();
}

#[test]
fn g2_the_ends_of_the_subordinate_range_are_asked_about_too() {
    let ids = fixture_ids(10001, 10003, 10002, 200_000, 65_536).unwrap();
    for chosen in [
        (IdKind::User, 10001),
        (IdKind::User, 10002),
        (IdKind::Group, 10003),
    ] {
        assert!(ids.contains(&chosen), "{chosen:?}");
    }
    for kind in [IdKind::User, IdKind::Group] {
        assert!(ids.contains(&(kind, 200_000)), "first, {kind:?}");
        assert!(ids.contains(&(kind, 265_535)), "last, {kind:?}");
        assert!(
            !ids.contains(&(kind, 265_536)),
            "one past the end, {kind:?}"
        );
    }
    // A name service that knows the last group id of the range refuses it.
    let proc = fake_proc(&[("1", "Uid:\t0\t0\t0\t0\n")]);
    let knows = |k: IdKind, i: u32| Ok(k == IdKind::Group && i == 265_535);
    let text = message(require_unused_ids(&ids, &knows, proc.path()));
    assert!(text.contains("group id 265535"), "{text}");
    // So does a process that runs as the first user id of the range.
    let proc = fake_proc(&[("77", "Uid:\t200000\t0\t0\t0\nGid:\t0\t0\t0\t0\n")]);
    let nobody = |_: IdKind, _: u32| Ok(false);
    let text = message(require_unused_ids(&ids, &nobody, proc.path()));
    assert!(text.contains("process 77"), "{text}");
    // An empty range and one that overflows have no end to ask about.
    assert!(fixture_ids(1, 2, 3, 200_000, 0).is_err());
    assert!(fixture_ids(1, 2, 3, u32::MAX - 10, 65_536).is_err());
}

#[test]
fn g2_getent_answers_for_an_id_every_host_has_and_one_none_has() {
    assert!(getent_knows(IdKind::User, 0).unwrap());
    assert!(getent_knows(IdKind::Group, 0).unwrap());
    assert!(!getent_knows(IdKind::User, 3_999_999_001).unwrap());
    assert!(!getent_knows(IdKind::Group, 3_999_999_002).unwrap());
}

/// G3: the flat identity files of an `etc`, written by the test.
fn flat_etc(passwd: &str, group: &str, subuid: &str, subgid: &str) -> tempfile::TempDir {
    let etc = tempfile::tempdir().unwrap();
    for (name, text) in [
        ("passwd", passwd),
        ("group", group),
        ("subuid", subuid),
        ("subgid", subgid),
    ] {
        fs::write(etc.path().join(name), text).unwrap();
    }
    etc
}

#[test]
fn g3_chosen_ids_and_ranges_must_be_nobodys_in_the_flat_files() {
    let ranges = [(3_000_000, 65_536), (3_100_000, 65_536)];
    let passwd = "root:x:0:0::/:/bin/sh\nrunner:x:1001:1001::/nonexistent:/bin/bash\n";
    let group = "root:x:0:\nrunner:x:1001:\n";
    let subids = "runner:100000:65536\n";
    let fine = flat_etc(passwd, group, subids, subids);
    require_free_ranges(fine.path(), &ranges, &IDS).unwrap();
    // A missing file holds nothing.
    let empty = tempfile::tempdir().unwrap();
    require_free_ranges(empty.path(), &ranges, &IDS).unwrap();
    // An account that already has a chosen id, as a user or as a group.
    let taken = flat_etc(&format!("{passwd}x:x:10002:5::/:/bin/sh\n"), group, "", "");
    assert!(message(require_free_ranges(taken.path(), &ranges, &IDS)).contains("10002"));
    let taken = flat_etc(passwd, &format!("{group}x:x:10003:\n"), "", "");
    assert!(message(require_free_ranges(taken.path(), &ranges, &IDS)).contains("10003"));
    // A user id that is the number of a chosen group is no clash.
    let other = flat_etc(&format!("{passwd}x:x:10003:5::/:/bin/sh\n"), group, "", "");
    require_free_ranges(other.path(), &ranges, &IDS).unwrap();
    // An account inside one of the ranges.
    let inside = flat_etc(
        &format!("{passwd}x:x:3100001:5::/:/bin/sh\n"),
        group,
        "",
        "",
    );
    assert!(message(require_free_ranges(inside.path(), &ranges, &IDS)).contains("3100001"));
    // A subordinate range that overlaps a chosen one, in subuid or in subgid.
    for (subuid, subgid) in [
        ("a:3065535:10\n", ""),
        ("", "b:2999999:2\n"),
        ("c:3000000:65536\n", ""),
        ("", "d:3150000:1\n"),
    ] {
        let overlap = flat_etc(passwd, group, subuid, subgid);
        let text = message(require_free_ranges(overlap.path(), &ranges, &IDS));
        assert!(text.contains("overlaps"), "{subuid}{subgid}: {text}");
    }
    // Next to a chosen range is not over it.
    let adjacent = flat_etc(passwd, group, "a:2934464:65536\n", "b:3065536:34464\n");
    require_free_ranges(adjacent.path(), &ranges, &IDS).unwrap();
    // A chosen id inside another account's range.
    let within = flat_etc(passwd, group, "e:10000:100\n", "");
    assert!(message(require_free_ranges(within.path(), &ranges, &IDS)).contains("e's range"));
    // A line of the files that is no range, or overflows, is refused.
    for bad in ["f:abc:10\n", "g:4294967290:100\n"] {
        let broken = flat_etc(passwd, group, bad, "");
        assert!(
            require_free_ranges(broken.path(), &ranges, &IDS).is_err(),
            "{bad}"
        );
    }
    // A comment is no range.
    let commented = flat_etc(passwd, group, "# a:3000000:9\n", "");
    require_free_ranges(commented.path(), &ranges, &IDS).unwrap();
    // A chosen range that overflows or is empty is no range.
    assert!(require_free_ranges(fine.path(), &[(u32::MAX - 1, 65_536)], &IDS).is_err());
    assert!(require_free_ranges(fine.path(), &[(3_000_000, 0)], &IDS).is_err());
}

#[test]
fn g4_the_copies_and_the_reserve_must_fit_and_the_refusal_says_by_how_much() {
    let dir = tempfile::tempdir().unwrap();
    let free = 5 << 30;
    require_space(dir.path(), 1 << 30, free).unwrap();
    require_space(dir.path(), free - RESERVE_BYTES, free).unwrap();
    let text = message(require_space(dir.path(), free - RESERVE_BYTES + 1, free));
    assert!(
        text.contains("5120 MiB free") && text.contains("1024 MiB must stay free"),
        "{text}"
    );
    assert!(text.contains("rm -r"), "{text}");
    // Nothing free at all, and sizes that would overflow.
    assert!(require_space(dir.path(), 0, 0).is_err());
    assert!(require_space(dir.path(), u64::MAX, u64::MAX).is_err());
    assert!(available_bytes(dir.path()).unwrap() > 0);
}

#[test]
fn g4_the_size_of_a_tree_counts_files_and_follows_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    fs::write(dir.path().join("a/one"), vec![0u8; 1000]).unwrap();
    fs::write(dir.path().join("a/b/two"), vec![0u8; 234]).unwrap();
    fs::write(dir.path().join("three"), vec![0u8; 10]).unwrap();
    symlink("/usr/bin", dir.path().join("a/link-to-a-big-tree")).unwrap();
    assert_eq!(tree_size(dir.path()).unwrap(), 1244);
    assert_eq!(tree_size(&dir.path().join("three")).unwrap(), 10);
    assert!(tree_size(&dir.path().join("absent")).is_err());
}

#[test]
fn g6_the_runtime_limit_defaults_to_an_hour_and_is_a_bounded_number_of_seconds() {
    let words = |text: &str| -> Vec<String> { text.split_whitespace().map(String::from).collect() };
    let none = words("a b c");
    assert_eq!(take_max_runtime(&none).unwrap(), (&none[..], 3600));
    let given = words("a b c --max-runtime 7200");
    let (rest, seconds) = take_max_runtime(&given).unwrap();
    assert_eq!((rest, seconds), (&given[..3], 7200));
    let low = words("--max-runtime 600");
    assert_eq!(take_max_runtime(&low).unwrap(), (&low[..0], 600));
    // The flag counts only at the end, and a value out of bounds or not a number is refused.
    let inside = words("a --max-runtime 7200 b");
    assert_eq!(take_max_runtime(&inside).unwrap().1, 3600);
    for bad in ["", "abc", "599", "86401", "-1", "1e4", "3600s"] {
        let args = vec!["a".to_owned(), "--max-runtime".to_owned(), bad.to_owned()];
        assert!(take_max_runtime(&args).is_err(), "{bad:?}");
    }
    assert!(take_max_runtime(&[]).is_ok());
}
