//! Explicit, one-thread privilege-boundary regression driver. The integration
//! owner supplies five owned numeric IDs: uid gid subuid-start subgid-start operator-uid.
//! Never run against global account files or a live service.
//!
//! Like the installed fixture's `create`, it refuses to run unless the operator
//! has said, on this machine, that it is disposable (`cat /etc/machine-id >
//! /etc/kronik-proof-host`, as root), and unless its ids and both 65,536-id
//! ranges belong to nobody: no account the name service knows, no running
//! process, no account or allocation in the flat identity files.
#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]

#[path = "support/proof_guard.rs"]
#[allow(dead_code)]
mod proof_guard;

use std::fs;
use std::io::{BufRead as _, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kronik_foreign::subid::{COUNT, Range};
use kronik_foreign::sys::{self, Acceptor, Pin};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capabilities(status: &str) -> [u64; 4] {
    ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"].map(|key| {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .expect("capability field");
        u64::from_str_radix(value.trim(), 16).expect("capability bits")
    })
}

fn status(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/status")).unwrap()
}
fn userns(pid: u32) -> PathBuf {
    fs::read_link(format!("/proc/{pid}/ns/user")).unwrap()
}

fn wait(child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(exit) = child.try_wait()? {
            if exit.success() {
                return Ok(());
            }
            return Err(format!("owned child {} failed: {exit}", child.id()).into());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("owned boundary child exceeded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_ready(child: &mut Child) -> Result<u32> {
    let stdout = child.stdout.take().ok_or("child stdout missing")?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .map(|_| line);
        let _ = tx.send(result);
    });
    let line = rx.recv_timeout(Duration::from_secs(10))??;
    Ok(line
        .strip_prefix("READY ")
        .ok_or("invalid readiness message")?
        .trim()
        .parse()?)
}

fn request(socket: &Path, uid: u32) -> Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    assert_eq!(answer, format!("{uid}\n"));
    Ok(())
}

fn mixed_identity(uid: u32) -> Result<()> {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    assert_eq!(rustix::process::geteuid().as_raw(), uid);
    let listener = UnixListener::bind("/run/kronik/mixed.sock")?;
    assert!(
        Acceptor::spawn(listener.into()).is_err(),
        "a real root UID can regain host authority"
    );
    Ok(())
}

fn drop_identity(uid: u32, gid: u32) -> Result<()> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
    assert!(sys::is_root());
    set_dumpable_behavior(DumpableBehavior::Dumpable)?;
    assert_eq!(dumpable_behavior()?, DumpableBehavior::Dumpable);
    sys::become_user(uid, gid)?;
    assert_eq!(rustix::process::geteuid().as_raw(), uid);
    assert_eq!(rustix::process::getegid().as_raw(), gid);
    assert_eq!(dumpable_behavior()?, DumpableBehavior::NotDumpable);
    assert_eq!(capabilities(&status(std::process::id())), [0, 0, 0, 0]);
    Ok(())
}

fn child(mode: &str, uid: u32, subuid: u32, subgid: u32) -> Result<()> {
    assert_eq!(rustix::process::geteuid().as_raw(), uid);
    let before = status(std::process::id());
    assert!(
        before
            .lines()
            .any(|l| l.starts_with("Threads:") && l.ends_with('1'))
    );
    assert!(
        capabilities(&before).iter().all(|c| c & (1 << 10) != 0),
        "startup bind capability was not supplied"
    );
    let unprivileged: u32 = fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")?
        .trim()
        .parse()?;
    assert!(
        unprivileged > 1,
        "private network namespace must enforce privileged ports"
    );
    // Positive control is confined to the proof child's fresh network namespace.
    drop(std::net::TcpListener::bind(("0.0.0.0", 1))?);
    let socket = Path::new("/run/kronik/probe.sock");
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666))?;
    let acceptor = Acceptor::spawn(listener.into())?;
    let initial = userns(std::process::id());
    // Independently prove acceptor clearing, then the daemon's authority
    // boundary, before creating its first runtime thread.
    sys::clear_capabilities()?;
    assert_eq!(capabilities(&status(std::process::id())), [0, 0, 0, 0]);
    let denied =
        std::net::TcpListener::bind(("0.0.0.0", 1)).expect_err("host bind capability survived");
    assert_eq!(denied.raw_os_error(), Some(13));
    if mode == "entered" {
        let mut maps = (
            sys::kronik_map(
                uid,
                Range {
                    start: subuid,
                    count: COUNT,
                },
            ),
            sys::kronik_map(
                rustix::process::getegid().as_raw(),
                Range {
                    start: subgid,
                    count: COUNT,
                },
            ),
        );
        maps.0[1][1] = kronik_foreign::subid::FLOOR - 1;
        assert!(sys::enter_userns(Path::new("/run/kronik-userns/user"), &maps).is_err());
        assert_eq!(
            userns(std::process::id()),
            initial,
            "unsafe map changed the calling namespace"
        );
        maps.0[1][1] = subuid;
        sys::enter_userns(Path::new("/run/kronik-userns/user"), &maps)?;
        assert_ne!(userns(std::process::id()), initial);
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
    } else {
        assert_eq!(mode, "degraded");
        assert!(
            sys::enter_userns(
                Path::new("/run/kronik-userns/missing"),
                &(
                    sys::kronik_map(
                        uid,
                        Range {
                            start: subuid,
                            count: COUNT
                        }
                    ),
                    sys::kronik_map(
                        rustix::process::getegid().as_raw(),
                        Range {
                            start: subgid,
                            count: COUNT
                        }
                    ),
                )
            )
            .is_err()
        );
        assert_eq!(userns(std::process::id()), initial);
    }
    let denied = std::net::TcpListener::bind(("0.0.0.0", 1))
        .expect_err("namespace entry regained host bind authority");
    assert_eq!(denied.raw_os_error(), Some(13));
    let entered = mode == "entered";
    std::thread::spawn(move || {
        let own = fs::read_to_string("/proc/thread-self/status").unwrap();
        if !entered {
            assert_eq!(capabilities(&own), [0, 0, 0, 0]);
        }
    })
    .join()
    .map_err(|_| "runtime thread retained host capabilities")?;
    println!("READY {}", acceptor.pid());
    std::io::stdout().flush()?;
    for _ in 0..3 {
        let (fd, peer_uid) = acceptor.recv()?;
        let mut stream = UnixStream::from(fd);
        writeln!(stream, "{peer_uid}")?;
    }
    let start = Instant::now();
    assert!(
        acceptor.recv().is_err(),
        "dead acceptor must fail, not silently lose API service"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    Ok(())
}

fn owned_proof(ids: [u32; 5]) -> Result<()> {
    let [uid, gid, subuid, subgid, operator] = ids;
    assert!(
        sys::is_root(),
        "this explicit proof requires its allocated setup authority"
    );
    assert!(uid != 0 && gid != 0 && operator != 0 && uid != operator);
    // The doors of the installed fixture's `create`: a machine declared
    // disposable, and ids and ranges that are nobody's.
    proof_guard::require_proof_host(
        Path::new(proof_guard::MARKER),
        Path::new(proof_guard::MACHINE_ID),
        0,
    )?;
    let mut ids = proof_guard::fixture_ids(uid, gid, operator, subuid, COUNT)?;
    ids.extend(proof_guard::fixture_ids(uid, gid, operator, subgid, COUNT)?);
    ids.sort_unstable_by_key(|&(kind, id)| (kind == proof_guard::IdKind::Group, id));
    ids.dedup();
    proof_guard::require_unused_ids(&ids, &proof_guard::getent_knows, Path::new("/proc"))?;
    proof_guard::require_free_ranges(
        Path::new("/etc"),
        &[(subuid, COUNT), (subgid, COUNT)],
        &[
            (proof_guard::IdKind::User, uid),
            (proof_guard::IdKind::User, operator),
            (proof_guard::IdKind::Group, gid),
        ],
    )?;
    let proof = tempfile::Builder::new()
        .prefix("kronik-boundary-")
        .tempdir_in("/var/tmp")?
        .keep();
    eprintln!(
        "boundary evidence (retained on failure): {}",
        proof.display()
    );
    let etc = proof.join("etc");
    let run = proof.join("run");
    for dir in [&etc, &run] {
        fs::create_dir(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(
        etc.join("passwd"),
        format!("root:x:0:0::/:/bin/false\nkronik:x:{uid}:{gid}::/:/bin/false\n"),
    )?;
    fs::write(etc.join("group"), format!("root:x:0:\nkronik:x:{gid}:\n"))?;
    fs::write(etc.join("subuid"), format!("kronik:{subuid}:{COUNT}\n"))?;
    fs::write(etc.join("subgid"), format!("kronik:{subgid}:{COUNT}\n"))?;
    fs::create_dir(run.join("kronik"))?;
    chown(run.join("kronik"), Some(uid), Some(gid))?;
    fs::set_permissions(run.join("kronik"), fs::Permissions::from_mode(0o755))?;
    sys::bootstrap_owned_rootless_fixture(&etc, &run)?;
    let pin = Path::new("/run/kronik-userns/user");
    let ranges = [
        Range {
            start: subuid,
            count: COUNT,
        },
        Range {
            start: subgid,
            count: COUNT,
        },
    ];
    assert_eq!(
        sys::pin_userns(uid, gid, ranges[0], ranges[1], pin)?,
        Pin::Created
    );
    let held = fs::File::open(pin)?;
    let identity = held.metadata()?;
    assert_eq!(
        sys::pin_userns(uid, gid, ranges[0], ranges[1], pin)?,
        Pin::Kept
    );
    assert!(
        sys::pin_userns(
            uid,
            gid,
            Range {
                start: subuid.checked_add(COUNT).ok_or("range overflow")?,
                count: COUNT
            },
            ranges[1],
            pin
        )
        .is_err()
    );
    assert_eq!(fs::metadata(pin)?.ino(), identity.ino());
    let record = pin.with_extension("owner");
    let creation = fs::read(&record)?;
    // A crash between the bind mount and the record leaves the pin without
    // it: `pin` writes it again (the namespace is the wanted one), and only
    // an absent record is repaired, as the lines below check.
    fs::remove_file(&record)?;
    assert!(sys::validate_owned_userns(pin).is_err());
    assert_eq!(
        sys::pin_userns(uid, gid, ranges[0], ranges[1], pin)?,
        Pin::Kept
    );
    assert_eq!(fs::read(&record)?, creation);
    fs::write(&record, "1 0 0 0\n")?;
    assert!(sys::unpin_userns(pin).is_err());
    fs::copy(std::env::current_exe()?, run.join("boundary-driver"))?;
    fs::set_permissions(
        run.join("boundary-driver"),
        fs::Permissions::from_mode(0o755),
    )?;
    assert_eq!(fs::metadata(pin)?.ino(), identity.ino());
    fs::write(&record, creation)?;
    let replacement = pin.with_file_name("replacement");
    assert_eq!(
        sys::pin_userns(uid, gid, ranges[0], ranges[1], &replacement)?,
        Pin::Created
    );
    let replacement_fd = fs::File::open(&replacement)?;
    let replacement_identity = replacement_fd.metadata()?;
    let mounted = Command::new("mount")
        .arg("--bind")
        .arg(&replacement)
        .arg(pin)
        .output()?;
    assert!(
        mounted.status.success(),
        "owned replacement mount: {mounted:?}"
    );
    assert_eq!(fs::metadata(pin)?.ino(), replacement_identity.ino());
    assert_eq!(
        held.metadata()?.ino(),
        identity.ino(),
        "open namespace FD followed a path replacement"
    );
    assert!(sys::validate_owned_userns(pin).is_err());
    assert!(sys::pin_userns(uid, gid, ranges[0], ranges[1], pin).is_err());
    assert!(
        sys::unpin_userns(pin).is_err(),
        "must not detach a replacement even with identical maps"
    );
    assert_eq!(fs::metadata(pin)?.ino(), replacement_identity.ino());
    // Detach only this runner's explicitly-created top bind, not the original pin.
    let unmounted = Command::new("umount")
        .args(["--lazy", "--no-canonicalize", "--"])
        .arg(pin)
        .output()?;
    assert!(
        unmounted.status.success(),
        "owned replacement detach: {unmounted:?}"
    );
    assert_eq!(fs::metadata(pin)?.ino(), identity.ino());
    assert!(sys::unpin_userns(&replacement)?);
    let plain = pin.with_file_name("preexisting");
    fs::write(&plain, "must survive\n")?;
    assert!(sys::unpin_userns(&plain).is_err());
    assert_eq!(fs::read_to_string(&plain)?, "must survive\n");
    let exe = PathBuf::from("/run/boundary-driver");
    let root_listener = UnixListener::bind("/run/kronik/root.sock")?;
    assert!(Acceptor::spawn(root_listener.into()).is_err());
    let mixed = Command::new("setpriv")
        .args([
            "--ruid",
            "0",
            "--euid",
            &uid.to_string(),
            "--regid",
            &gid.to_string(),
            "--clear-groups",
        ])
        .arg(&exe)
        .args(["mixed-ids", &uid.to_string()])
        .output()?;
    fs::write(proof.join("mixed-ids.stderr"), &mixed.stderr)?;
    assert!(mixed.status.success(), "mixed-ID refusal failed: {mixed:?}");
    let dropped = Command::new(&exe)
        .env_clear()
        .args(["drop-identity", &uid.to_string(), &gid.to_string()])
        .output()?;
    fs::write(proof.join("drop-identity.stderr"), &dropped.stderr)?;
    assert!(
        dropped.status.success(),
        "protected identity drop failed: {dropped:?}"
    );
    for mode in ["entered", "degraded"] {
        let stderr = fs::File::create(proof.join(format!("{mode}.stderr")))?;
        let mut owned = Reap(
            Command::new("unshare")
                .args(["--net", "--", "setpriv"])
                .args([
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &gid.to_string(),
                    "--clear-groups",
                    "--inh-caps=+net_bind_service",
                    "--ambient-caps=+net_bind_service",
                ])
                .arg(&exe)
                .args([
                    "child",
                    mode,
                    &uid.to_string(),
                    &subuid.to_string(),
                    &subgid.to_string(),
                ])
                .stdout(Stdio::piped())
                .stderr(stderr)
                .spawn()?,
        );
        let daemon = &mut owned.0;
        let result = (|| -> Result<()> {
            let acceptor = read_ready(daemon)?;
            let process = status(acceptor);
            assert_eq!(capabilities(&process), [0, 0, 0, 0]);
            let mut values = process
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .unwrap()
                .split_whitespace();
            let uids: [u32; 4] = std::array::from_fn(|_| values.next().unwrap().parse().unwrap());
            assert_eq!(uids, [uid; 4]);
            assert!(values.next().is_none());
            assert_eq!(userns(acceptor), userns(std::process::id()));
            fs::write(proof.join(format!("{mode}.acceptor-status")), process)?;
            assert_eq!(
                sys::pin_userns(uid, gid, ranges[0], ranges[1], pin)?,
                Pin::Kept
            );
            assert_eq!(
                fs::metadata(pin)?.ino(),
                identity.ino(),
                "pin restart moved a live daemon to a replacement namespace"
            );
            let socket = Path::new("/run/kronik/probe.sock");
            request(socket, 0)?;
            for peer in [operator, uid] {
                let out = Command::new("setpriv")
                    .args([
                        "--reuid",
                        &peer.to_string(),
                        "--regid",
                        &peer.to_string(),
                        "--clear-groups",
                    ])
                    .arg(&exe)
                    .args(["client", socket.to_str().unwrap(), &peer.to_string()])
                    .output()?;
                assert!(out.status.success(), "peer {peer}: {out:?}");
            }
            let killed = Command::new("kill")
                .args(["-KILL", &acceptor.to_string()])
                .status()?;
            assert!(killed.success());
            wait(daemon)
        })();
        result?;
    }
    assert!(sys::unpin_userns(pin)?);
    assert!(sys::inspect_userns(pin)?.is_none());
    assert_eq!(
        (held.metadata()?.dev(), held.metadata()?.ino()),
        (identity.dev(), identity.ino()),
        "held namespace FD changed during unpin"
    );
    assert!(!sys::unpin_userns(pin)?);
    fs::remove_file(plain)?;
    // The mounts and private identity view die with this short-lived proof process.
    println!(
        "namespace identity, owned unpin, startup caps, true peer UIDs and acceptor death: pass; evidence {}",
        proof.display()
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = (|| -> Result<()> {
        match args.first().map(String::as_str) {
            Some("child") if args.len() == 5 => child(&args[1], args[2].parse()?, args[3].parse()?, args[4].parse()?),
            Some("client") if args.len() == 3 => request(Path::new(&args[1]), args[2].parse()?),
            Some("mixed-ids") if args.len() == 2 => mixed_identity(args[1].parse()?),
            Some("drop-identity") if args.len() == 3 => drop_identity(args[1].parse()?, args[2].parse()?),
            _ if args.len() == 5 => owned_proof([args[0].parse()?, args[1].parse()?, args[2].parse()?, args[3].parse()?, args[4].parse()?]),
            _ => Err("usage: rootless_boundary OWNED_UID OWNED_GID SUBUID_START SUBGID_START OPERATOR_UID".into()),
        }
    })();
    if let Err(error) = result {
        eprintln!("rootless boundary failed: {error}");
        std::process::exit(1);
    }
}
