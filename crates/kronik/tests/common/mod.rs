//! Shared by the tests that start `kronik serve` on TCP ports.

use std::collections::hash_map::RandomState;
use std::fs::{File, OpenOptions, Permissions};
use std::hash::{BuildHasher, Hasher};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Mutex;

/// Where every test process claims the ports it hands out, whatever its
/// target directory.
const CLAIMS_DIR: &str = "/var/tmp/kronik-test-ports";

/// The claims of this process, held until it exits.
static CLAIMS: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// A port for `kronik serve` to bind later.
///
/// A port that `bind(127.0.0.1:0)` found free can be taken before the
/// daemon binds it, by a concurrent test or by the kernel, which hands the
/// ports of its ephemeral range to other `bind(0)` and `connect` calls; the
/// daemon then stops with "Address already in use". So the port comes from
/// below the ephemeral range, which the kernel never hands out. It is free
/// now, and it is claimed with a lock in [`CLAIMS_DIR`] that every test
/// process honours until this one exits.
pub fn free_port() -> u16 {
    let dir = Path::new(CLAIMS_DIR);
    std::fs::create_dir_all(dir).unwrap();
    // Every user's test runs share it, as they share /tmp.
    let _ = std::fs::set_permissions(dir, Permissions::from_mode(0o1777));
    let (low, high) = below_ephemeral();
    for _ in 0..10_000 {
        let port =
            low + (RandomState::new().build_hasher().finish() % u64::from(high - low)) as u16;
        // A claim another user's run made can't be opened here: taken too.
        let Ok(claim) = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(port.to_string()))
        else {
            continue;
        };
        if claim.try_lock().is_ok() && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            CLAIMS.lock().unwrap().push(claim);
            return port;
        }
    }
    panic!("no free port in {low}..{high}");
}

/// The ports below the kernel's ephemeral range (32768 to 60999 by
/// default), down to half its start.
fn below_ephemeral() -> (u16, u16) {
    let start: u16 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768);
    assert!(
        start >= 4096,
        "the ephemeral port range starts at {start}: no room below it for test ports"
    );
    (start / 2, start)
}
