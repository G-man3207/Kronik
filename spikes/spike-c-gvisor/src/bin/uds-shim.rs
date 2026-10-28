//! Forwards connections from a Unix socket to a TCP address. Kronik would
//! run it inside the sandbox when a foreign actor only listens on TCP.
//!
//! Usage:
//!   uds-shim --listen-unix PATH --connect HOST:PORT
//!   uds-shim --listen-fd N --connect HOST:PORT
//!
//! With `--listen-unix` the shim binds PATH; when PATH is in a bind-mounted
//! directory and runsc runs with `--host-uds=create`, the socket appears on
//! the host. With `--listen-fd` the shim accepts on an already listening
//! socket that the host created and passed in (`runsc exec --pass-fd`).

use std::io;
use std::net::{Shutdown, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (listener, target) = match args.as_slice() {
        [_, l, path, c, target] if l == "--listen-unix" && c == "--connect" => {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).unwrap_or_else(|e| {
                eprintln!("uds-shim: bind {path}: {e}");
                std::process::exit(1);
            });
            println!("uds-shim: forwarding unix {path} to tcp {target}");
            (listener, target.clone())
        }
        [_, l, fd, c, target] if l == "--listen-fd" && c == "--connect" => {
            let fd: i32 = fd.parse().unwrap_or_else(|_| {
                eprintln!("uds-shim: bad fd {fd}");
                std::process::exit(2);
            });
            // SAFETY: the caller passes a listening Unix socket as fd `fd`
            // and nothing else in this process uses that descriptor.
            let listener = UnixListener::from(unsafe { OwnedFd::from_raw_fd(fd) });
            println!("uds-shim: forwarding inherited fd {fd} to tcp {target}");
            (listener, target.clone())
        }
        _ => {
            eprintln!("usage: uds-shim (--listen-unix PATH | --listen-fd N) --connect HOST:PORT");
            std::process::exit(2);
        }
    };
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let target = target.clone();
                thread::spawn(move || {
                    if let Err(e) = forward(stream, &target) {
                        eprintln!("uds-shim: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("uds-shim: accept: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn forward(unix: UnixStream, target: &str) -> io::Result<()> {
    let tcp = TcpStream::connect(target)?;
    tcp.set_nodelay(true)?;
    let (mut unix_read, mut unix_write) = (unix.try_clone()?, unix);
    let (mut tcp_read, mut tcp_write) = (tcp.try_clone()?, tcp);
    let upstream = thread::spawn(move || {
        let _ = io::copy(&mut unix_read, &mut tcp_write);
        let _ = tcp_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut tcp_read, &mut unix_write);
    let _ = unix_write.shutdown(Shutdown::Write);
    let _ = upstream.join();
    Ok(())
}
