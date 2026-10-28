//! Tries to reach the outside world and reports what happened. Run inside
//! the sandbox to prove that egress is blocked.
//!
//! Usage: netprobe [EXTRA_TCP_TARGET]...
//! Exits 0 if every attempt failed, 1 if any succeeded.

use std::fs;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    println!("== network interfaces (/proc/net/dev)");
    print!(
        "{}",
        fs::read_to_string("/proc/net/dev").unwrap_or_else(|e| format!("<{e}>\n"))
    );
    println!("== IPv4 routes (/proc/net/route)");
    print!(
        "{}",
        fs::read_to_string("/proc/net/route").unwrap_or_else(|e| format!("<{e}>\n"))
    );
    println!("== IPv6 addresses (/proc/net/if_inet6)");
    print!(
        "{}",
        fs::read_to_string("/proc/net/if_inet6").unwrap_or_else(|e| format!("<{e}>\n"))
    );
    println!(
        "== /etc/resolv.conf: {}",
        fs::read_to_string("/etc/resolv.conf")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|e| format!("<{e}>"))
    );

    let mut leaks = 0;
    let mut tcp: Vec<String> = ["1.1.1.1:443", "8.8.8.8:53", "[2606:4700:4700::1111]:443"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    tcp.extend(std::env::args().skip(1));
    println!("== outbound TCP");
    for target in &tcp {
        let addr: SocketAddr = match target.parse() {
            Ok(a) => a,
            Err(e) => {
                println!("tcp {target}: bad address: {e}");
                continue;
            }
        };
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(_) => {
                leaks += 1;
                println!(
                    "tcp {target}: CONNECTED after {:?} (egress is open)",
                    start.elapsed()
                );
            }
            Err(e) => println!("tcp {target}: blocked after {:?}: {e}", start.elapsed()),
        }
    }

    println!("== outbound UDP DNS query for example.com");
    for server in ["8.8.8.8:53", "1.1.1.1:53", "100.100.100.100:53"] {
        let start = Instant::now();
        match dns_query(server) {
            Ok(n) => {
                leaks += 1;
                println!(
                    "udp {server}: ANSWERED with {n} bytes after {:?} (egress is open)",
                    start.elapsed()
                );
            }
            Err(e) => println!("udp {server}: blocked after {:?}: {e}", start.elapsed()),
        }
    }

    println!("== resolver lookup of example.com:443");
    let start = Instant::now();
    match ("example.com", 443).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            leaks += 1;
            println!(
                "resolved to {addrs:?} after {:?} (DNS works)",
                start.elapsed()
            );
        }
        Err(e) => println!("lookup failed after {:?}: {e}", start.elapsed()),
    }

    if leaks == 0 {
        println!(
            "RESULT: egress blocked (0 of {} attempts succeeded)",
            tcp.len() + 4
        );
    } else {
        println!("RESULT: EGRESS OPEN ({leaks} attempts succeeded)");
        std::process::exit(1);
    }
}

fn dns_query(server: &str) -> std::io::Result<usize> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    socket.send_to(&query, server)?;
    let mut buf = [0u8; 512];
    let (n, _) = socket.recv_from(&mut buf)?;
    Ok(n)
}
