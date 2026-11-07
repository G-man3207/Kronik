//! Ordinary hostile filesystem/network/process/IPC operations, with positive controls.
//! No operation replaces an existing file, changes a mount, or changes a hostname.
#[allow(dead_code)]
#[path = "../../foreign-echo/src/http.rs"]
mod http;
mod sys;

use http::{Request, Response};
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(1);
const PATH_ERRORS: &[i32] = &[libc::ENOENT, libc::ENOTDIR, libc::EACCES, libc::EPERM];
const NET_ERRORS: &[i32] = &[
    libc::EACCES,
    libc::EPERM,
    libc::ENOENT,
    libc::ECONNREFUSED,
    libc::ENETUNREACH,
    libc::EHOSTUNREACH,
    libc::ETIMEDOUT,
    libc::EAFNOSUPPORT,
    libc::EADDRNOTAVAIL,
    libc::EAGAIN,
];
const DNS_QUERY: &[u8] =
    b"\x72\x91\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05owned\x07invalid\x00\x00\x01\x00\x01";

fn token_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--hold-token") {
        thread::sleep(Duration::from_secs(900));
        return Ok(());
    }
    let token = std::env::var("KRONIK_PROBE_TOKEN")
        .map_err(|_| io::Error::other("KRONIK_PROBE_TOKEN is required"))?;
    if !token_ok(&token) {
        return Err(io::Error::other("invalid unique token"));
    }
    // Make the positive process control observable in /proc, not merely in its reply.
    if !args
        .windows(2)
        .any(|a| a[0] == "--identity" && a[1] == token)
    {
        return Err(std::process::Command::new(std::env::current_exe()?)
            .args(&args[1..])
            .args(["--identity", &token])
            .exec());
    }
    let listen = args
        .windows(2)
        .find(|a| a[0] == "--listen")
        .map_or("0.0.0.0:8080", |a| a[1].as_str());
    let controls = Controls::new(&token)?;
    let listener = TcpListener::bind(listen)?;
    // Serial requests bound both threads and concurrent DNS work.
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        if let Ok(Some(request)) = http::read_request(&mut reader, 0) {
            let response = route(&request, &controls);
            http::write_response(&mut stream, &response, false, false)?;
        }
    }
    Ok(())
}

struct Controls {
    token: String,
    tcp: TcpListener,
    udp: UdpSocket,
    abstract_socket: UnixListener,
    sysv: sys::SharedMemory,
    child: std::process::Child,
}

impl Controls {
    fn new(token: &str) -> io::Result<Self> {
        let marker = format!("/data/owned-{token}");
        let shm = format!("/dev/shm/owned-{token}");
        exclusive_marker(&marker, token)?;
        exclusive_marker(&shm, token)?;
        // Token-derived private ports let the harness exclude cross-control collisions.
        let port = 20000 + u16::from_str_radix(&token[..4], 16).map_err(io::Error::other)? % 40000;
        let tcp = TcpListener::bind(("127.0.0.1", port))?;
        let udp = UdpSocket::bind(("127.0.0.1", port))?;
        let abstract_socket =
            UnixListener::bind_addr(&UnixAddr::from_abstract_name(token.as_bytes())?)?;
        let sysv = sys::SharedMemory::new(token)?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--hold-token", token])
            .spawn()?;
        Ok(Self {
            token: token.into(),
            tcp,
            udp,
            abstract_socket,
            sysv,
            child,
        })
    }
}

impl Drop for Controls {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn exclusive_marker(path: &str, token: &str) -> io::Result<()> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(token.as_bytes())?;
            file.sync_all()
        }
        // Restart may retain /data. Never truncate a retained marker.
        Err(e)
            if e.kind() == io::ErrorKind::AlreadyExists && fs::read(path)? == token.as_bytes() =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

struct Item {
    target: String,
    outcome: &'static str,
    detail: String,
    errno: Option<i32>,
}
impl Item {
    fn seen(target: &str, detail: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            outcome: "reached",
            detail: detail.into(),
            errno: None,
        }
    }
    fn failed(target: &str, error: io::Error, expected: &[i32]) -> Self {
        let errno = error.raw_os_error();
        let outcome = if errno.is_some_and(|e| expected.contains(&e)) {
            "blocked"
        } else {
            "error"
        };
        Self {
            target: target.into(),
            outcome,
            detail: error.to_string(),
            errno,
        }
    }
    fn absent(target: &str, detail: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            outcome: "absent",
            detail: detail.into(),
            errno: None,
        }
    }
    fn json(&self) -> String {
        format!(
            "{{\"target\":{},\"outcome\":{},\"detail\":{},\"errno\":{}}}",
            js(&self.target),
            js(self.outcome),
            js(&self.detail),
            self.errno.map_or("null".into(), |n| n.to_string())
        )
    }
}

fn route(request: &Request, own: &Controls) -> Response {
    if request.method != "GET" {
        return Response::text(405, "GET required");
    }
    if request.path() == "/healthz" {
        return Response::text(200, "ok");
    }
    if request.path() == "/check/fill-data" {
        let Some(token) = request.query("token").filter(|s| token_ok(s)) else {
            return Response::text(400, "unique token required");
        };
        return match fill_data(own, &token) {
            Ok(report) => Response::json(200, report),
            Err(error) => Response::json(
                500,
                format!(
                    "{{\"check\":\"/check/fill-data\",\"error\":{},\"errno\":{}}}",
                    js(&error.to_string()),
                    error
                        .raw_os_error()
                        .map_or("null".into(), |n| n.to_string())
                ),
            ),
        };
    }
    let q = |name| request.query_all(name);
    let items: Vec<Item> = match request.path() {
        "/check/control" => control(own),
        "/check/paths" => q("path").iter().map(|p| read_path(p, None)).collect(),
        "/check/marker" => {
            let Some(token) = request.query("token").filter(|s| token_ok(s)) else {
                return Response::text(400, "token required");
            };
            q("path")
                .iter()
                .map(|p| read_path(p, Some(&token)))
                .collect()
        }
        "/check/write" => {
            let Some(token) = request.query("token").filter(|s| token_ok(s)) else {
                return Response::text(400, "token required");
            };
            q("dir")
                .iter()
                .map(|dir| write_canary(dir, &token))
                .collect()
        }
        "/check/network" => {
            let mut items: Vec<Item> = q("tcp").iter().map(|p| tcp(p)).collect();
            items.extend(q("udp").iter().map(|p| udp(p)));
            items.extend(q("unix").iter().map(|p| unix(p)));
            items.extend(q("abstract").iter().map(|p| abstract_socket(p)));
            items
        }
        "/check/processes" => {
            let Some(token) = request.query("token").filter(|s| token_ok(s)) else {
                return Response::text(400, "token required");
            };
            vec![processes(&token)]
        }
        "/check/sysv" => q("key").iter().map(|k| sys::lookup(k)).collect(),
        "/check/devices" => [
            "/dev/kvm",
            "/dev/sda",
            "/dev/vda",
            "/dev/vdb",
            "/dev/nvme0n1",
            "/dev/mem",
        ]
        .iter()
        .map(|p| match fs::File::open(p) {
            Ok(_) => Item::seen(p, "opened device"),
            Err(e) => Item::failed(p, e, PATH_ERRORS),
        })
        .collect(),
        "/check/guest-disks" => [
            "/sys/class/block/vda/ro",
            "/sys/class/block/vdb/size",
            "/proc/self/mountinfo",
        ]
        .iter()
        .map(|p| read_path(p, None))
        .collect(),
        "/check/identity" => {
            let mut items: Vec<Item> = [
                "/proc/self/status",
                "/proc/self/cgroup",
                "/proc/sys/kernel/hostname",
            ]
            .iter()
            .map(|p| read_path(p, None))
            .collect();
            for ns in ["user", "mnt", "net", "pid", "ipc", "uts", "cgroup"] {
                let p = format!("/proc/self/ns/{ns}");
                items.push(match fs::read_link(&p) {
                    Ok(v) => Item::seen(&p, v.to_string_lossy()),
                    Err(e) => Item::failed(&p, e, &[]),
                });
            }
            items
        }
        _ => return Response::text(404, "unknown check"),
    };
    if items.is_empty() {
        return Response::text(400, "at least one target required");
    }
    let outcome = if items.iter().any(|i| i.outcome == "error") {
        "error"
    } else if items.iter().any(|i| i.outcome == "reached") {
        "reached"
    } else {
        "blocked"
    };
    Response::json(
        200,
        format!(
            "{{\"check\":{},\"outcome\":{},\"items\":[{}]}}",
            js(request.path()),
            js(outcome),
            items.iter().map(Item::json).collect::<Vec<_>>().join(",")
        ),
    )
}

fn read_path(path: &str, marker: Option<&str>) -> Item {
    let result = (|| -> io::Result<String> {
        let md = fs::metadata(path)?;
        if md.is_dir() {
            let mut count = 0usize;
            for entry in fs::read_dir(path)? {
                entry?;
                count += 1;
                if count > 1_000_000 {
                    return Err(io::Error::other("directory entry limit exceeded"));
                }
            }
            return Ok(format!("{count} entries"));
        }
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(io::Error::other("read limit exceeded"));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })();
    match result {
        Ok(s) if marker.is_some_and(|m| !s.contains(m)) => Item::absent(path, "marker not present"),
        Ok(s) => Item::seen(path, s),
        Err(e) => Item::failed(path, e, PATH_ERRORS),
    }
}

fn fill_data(own: &Controls, token: &str) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt as _;
    const CAPACITY: u64 = 1 << 30;
    let sectors = fs::read_to_string("/sys/class/block/vdb/size")?
        .trim()
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if sectors.checked_mul(512) != Some(CAPACITY) {
        return Err(io::Error::other(
            "fill requires the fixed owned 1GiB guest disk",
        ));
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    if !mounts.lines().any(|line| {
        line.split_whitespace().nth(4) == Some("/data")
            && line
                .split_once(" - ")
                .is_some_and(|(_, fs)| fs.split_whitespace().next() == Some("ext4"))
    }) {
        return Err(io::Error::other(
            "fill requires the owned guest ext4 /data mount",
        ));
    }
    let marker = Path::new("/data").join(format!("owned-{}", own.token));
    let before = fs::read(&marker)?;
    if before != own.token.as_bytes() {
        return Err(io::Error::other("own marker changed before fill"));
    }
    fs::File::open(&marker)?.sync_all()?;
    let directory = fs::File::open("/data")?;
    directory.sync_all()?;
    let path = Path::new("/data").join(format!("fill-{token}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let identity = file.metadata()?;
    let result = (|| -> io::Result<(u64, i32)> {
        let block = [0xa5u8; 65536];
        let mut bytes = 0u64;
        while bytes < CAPACITY + (1 << 20) {
            let remaining = (CAPACITY + (1 << 20) - bytes) as usize;
            match file.write(&block[..block.len().min(remaining)]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "fill made no progress",
                    ));
                }
                Ok(n) => bytes += n as u64,
                Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                    // A full-filesystem sync may repeat ENOSPC, never another error.
                    if let Err(sync) = file.sync_all()
                        && sync.raw_os_error() != Some(libc::ENOSPC)
                    {
                        return Err(sync);
                    }
                    return Ok((bytes, libc::ENOSPC));
                }
                Err(error) => return Err(error),
            }
        }
        match file.sync_all() {
            Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => Ok((bytes, libc::ENOSPC)),
            Err(error) => Err(error),
            Ok(()) => Err(io::Error::other(
                "fixed guest disk accepted more than its capacity without ENOSPC",
            )),
        }
    })();
    let unchanged = fs::read(&marker).map(|after| after == before);
    drop(file);
    let named = fs::symlink_metadata(&path)?;
    if (named.dev(), named.ino(), named.nlink()) != (identity.dev(), identity.ino(), 1) {
        return Err(io::Error::other("fill file replaced; refusing cleanup"));
    }
    fs::remove_file(&path)?;
    directory.sync_all()?;
    let (bytes, error) = result?;
    if !unchanged? {
        return Err(io::Error::other(
            "filling guest disk damaged the existing marker",
        ));
    }
    Ok(format!(
        "{{\"check\":\"/check/fill-data\",\"capacity_bytes\":{CAPACITY},\"written_bytes\":{bytes},\"errno\":{error},\"marker_unchanged\":true,\"cleanup\":true}}"
    ))
}

fn write_canary(dir: &str, token: &str) -> Item {
    let path = Path::new(dir).join(format!(".kronik-probe-{token}"));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| {
            f.write_all(token.as_bytes())?;
            f.sync_all()
        });
    match result {
        Ok(()) => Item::seen(
            &path.to_string_lossy(),
            "created exclusively; left for host observation",
        ),
        Err(e) => Item::failed(
            &path.to_string_lossy(),
            e,
            &[
                libc::ENOENT,
                libc::ENOTDIR,
                libc::EACCES,
                libc::EPERM,
                libc::EROFS,
            ],
        ),
    }
}

fn tcp(target: &str) -> Item {
    let addr: SocketAddr = match target.parse() {
        Ok(a) => a,
        Err(e) => return Item::failed(target, io::Error::other(e), &[]),
    };
    match TcpStream::connect_timeout(&addr, TIMEOUT) {
        Ok(_) => Item::seen(target, "connected"),
        Err(e) => Item::failed(target, e, NET_ERRORS),
    }
}

fn udp(target: &str) -> Item {
    let result = (|| -> io::Result<()> {
        let addr: SocketAddr = target.parse().map_err(io::Error::other)?;
        let socket = UdpSocket::bind(if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.connect(addr)?;
        // An actual DNS A query. Any host receipt is independently a harness failure.
        let query = DNS_QUERY;
        if socket.send(query)? != query.len() {
            return Err(io::Error::other("partial DNS datagram"));
        }
        let mut reply = [0u8; 512];
        let n = socket.recv(&mut reply)?;
        if n != query.len() + 16
            || reply[..2] != query[..2]
            || reply[2..4] != [0x81, 0x80]
            || reply[6..8] != [0, 1]
            || reply[n - 4..n] != [127, 0, 0, 1]
        {
            return Err(io::Error::other("invalid DNS A response"));
        }
        Ok(())
    })();
    match result {
        Ok(()) => Item::seen(target, "DNS reply"),
        Err(e) => Item::failed(target, e, NET_ERRORS),
    }
}

fn unix(target: &str) -> Item {
    match UnixStream::connect(target) {
        Ok(_) => Item::seen(target, "connected"),
        Err(e) => Item::failed(target, e, NET_ERRORS),
    }
}
fn abstract_socket(target: &str) -> Item {
    match UnixAddr::from_abstract_name(target.as_bytes()).and_then(|a| UnixStream::connect_addr(&a))
    {
        Ok(_) => Item::seen(target, "connected"),
        Err(e) => Item::failed(target, e, NET_ERRORS),
    }
}

fn processes(token: &str) -> Item {
    let result = (|| -> io::Result<Vec<String>> {
        let mut matches = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
            {
                continue;
            }
            match fs::read(entry.path().join("cmdline")) {
                Ok(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    if line.contains(token) {
                        matches.push(line.replace('\0', " "));
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {} // exited during enumeration
                Err(e) => return Err(e),
            }
        }
        Ok(matches)
    })();
    match result {
        Ok(v) if v.is_empty() => Item::absent(token, "enumerated /proc; no matching process"),
        Ok(v) => Item::seen(token, v.join("\n")),
        Err(e) => Item::failed(token, e, &[]),
    }
}

fn control(own: &Controls) -> Vec<Item> {
    let mut items = vec![
        read_path(&format!("/data/owned-{}", own.token), Some(&own.token)),
        read_path(&format!("/dev/shm/owned-{}", own.token), Some(&own.token)),
        processes(&own.token),
        tcp(&own.tcp.local_addr().unwrap().to_string()),
        abstract_socket(&own.token),
        sys::lookup(&own.sysv.key.to_string()),
    ];
    if !items[2].detail.contains("--hold-token") {
        items[2] = Item::failed(
            "own child process",
            io::Error::other("child argv not observed in /proc"),
            &[],
        );
    }
    // Positive DNS control uses a real listener and response, not an invented errno.
    let socket = own.udp.try_clone().unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    // The probe is a plain program inside a sandbox, not daemon code: it has no
    // Env, and the repository's disallowed-methods list (ADR 0004) is for the daemon.
    #[allow(clippy::disallowed_methods)]
    let responder = thread::spawn(move || -> io::Result<()> {
        let mut bytes = [0u8; 512];
        let (n, from) = socket.recv_from(&mut bytes)?;
        if n != DNS_QUERY.len() || bytes[..n] != *DNS_QUERY {
            return Err(io::Error::other("unexpected owned DNS question"));
        }
        bytes[2..4].copy_from_slice(&[0x81, 0x80]);
        bytes[6..8].copy_from_slice(&[0, 1]);
        // A real compressed-name A answer for the owned .invalid test zone.
        bytes[n..n + 16].copy_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
        socket.send_to(&bytes[..n + 16], from)?;
        Ok(())
    });
    items.push(udp(&own.udp.local_addr().unwrap().to_string()));
    match responder.join() {
        Ok(Ok(())) => {}
        _ => items.push(Item::failed(
            "own DNS responder",
            io::Error::other("responder failed"),
            &[],
        )),
    }
    // Opening null and reading random prove device operations actually execute.
    items.push(
        match OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .and_then(|mut f| f.write_all(b"control"))
        {
            Ok(()) => Item::seen("/dev/null", "wrote control"),
            Err(e) => Item::failed("/dev/null", e, &[]),
        },
    );
    items.push(
        match fs::File::open("/dev/urandom").and_then(|mut f| {
            let mut b = [0u8; 16];
            f.read_exact(&mut b)
        }) {
            Ok(()) => Item::seen("/dev/urandom", "read 16 bytes"),
            Err(e) => Item::failed("/dev/urandom", e, &[]),
        },
    );
    // Drain listener backlogs so repeated controls remain meaningful.
    own.tcp.set_nonblocking(true).unwrap();
    while own.tcp.accept().is_ok() {}
    own.abstract_socket.set_nonblocking(true).unwrap();
    while own.abstract_socket.accept().is_ok() {}
    items
}

fn js(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_unexpected_errno_is_not_absence() {
        let e = fs::File::open("/proc/self/status/not-a-directory").unwrap_err();
        let item = Item::failed("real ENOTDIR", e, &[libc::ENOENT]);
        assert_eq!(item.outcome, "error");
        assert_eq!(item.errno, Some(libc::ENOTDIR));
        let e = fs::File::open("/proc/self/kronik-no-such-entry").unwrap_err();
        assert_eq!(Item::failed("missing", e, PATH_ERRORS).outcome, "blocked");
    }
    #[test]
    fn exclusive_canary_never_overwrites() {
        let token = format!("exclusive-probe-{}", std::process::id());
        let dir = std::env::temp_dir().join(&token);
        fs::create_dir(&dir).unwrap();
        let path = dir.join(format!(".kronik-probe-{token}"));
        fs::write(&path, "preexisting").unwrap();
        assert_eq!(write_canary(dir.to_str().unwrap(), &token).outcome, "error");
        assert_eq!(fs::read_to_string(&path).unwrap(), "preexisting");
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
