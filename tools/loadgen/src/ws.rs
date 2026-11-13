//! A minimal RFC 6455 WebSocket client over a blocking `TcpStream`, without
//! dependencies: the opening handshake with the `Sec-WebSocket-Accept`
//! check, masked text, pong and close frames, and unmasked server frames
//! (fragmented or not) up to a size cap. No extensions, no subprotocols.
//! Pings are answered inside [`Client::read`].

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The largest message accepted from the server.
pub const MAX_MESSAGE: usize = 1 << 20;
const HEADER_CAP: usize = 16 * 1024;
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// xorshift64*: masking keys and handshake nonces. RFC 6455 asks for
/// unpredictable masks to protect intermediaries from a hostile script; a
/// load generator talking to its own server needs no more than this.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // splitmix64 of the seed, so that nearby seeds give unrelated streams
        // and the state is never zero.
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Rng((z ^ (z >> 31)) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

/// SHA-1, for the handshake's accept value only.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Standard base64 with padding.
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> shift) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{key}{GUID}").as_bytes()))
}

/// One message from the server. Pings are answered and pongs ignored inside
/// [`Client::read`], so they never show up here.
#[derive(Debug, PartialEq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    /// The server's close frame: its code (1005 when it had none) and reason.
    Close(u16, String),
}

/// A frame header and where its payload is in a buffer.
#[derive(Debug, PartialEq)]
struct Frame {
    fin: bool,
    opcode: u8,
    start: usize,
    end: usize,
}

/// Parses one server frame at the start of `buf`: `Ok(None)` when more bytes
/// are needed.
fn parse_frame(buf: &[u8]) -> Result<Option<Frame>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        return Err("frame with reserved bits set".into());
    }
    let opcode = buf[0] & 0x0f;
    if buf[1] & 0x80 != 0 {
        return Err("masked frame from the server".into());
    }
    let (len, header) = match buf[1] & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(b), 10)
        }
        n => (u64::from(n), 2),
    };
    if opcode >= 8 && (!fin || len > 125) {
        return Err("fragmented or oversized control frame".into());
    }
    if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err(format!("unknown opcode {opcode}"));
    }
    if len > MAX_MESSAGE as u64 {
        return Err(format!("frame of {len} bytes exceeds {MAX_MESSAGE}"));
    }
    let end = header + len as usize;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some(Frame {
        fin,
        opcode,
        start: header,
        end,
    }))
}

/// A client frame: FIN, the opcode, and the payload masked with a fresh key.
fn encode_frame(opcode: u8, payload: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(0x80 | n as u8),
        n if n <= 0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mut mask = [0u8; 4];
    rng.fill(&mut mask);
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// What [`Client::connect`] got back when the server did not switch
/// protocols, or the handshake failed.
#[derive(Debug)]
pub enum ConnectError {
    /// The server answered with an HTTP status other than 101.
    Status(u16),
    Other(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Status(status) => write!(f, "handshake answered HTTP {status}"),
            ConnectError::Other(e) => f.write_str(e),
        }
    }
}

pub struct Client {
    stream: TcpStream,
    /// Received bytes not yet parsed.
    buf: Vec<u8>,
    /// The payload of a fragmented message in progress, with its opcode.
    partial: Option<(u8, Vec<u8>)>,
    rng: Rng,
}

impl Client {
    /// Opens a connection and performs the handshake for `path` within
    /// `timeout`. `host` is the `Host` header; `origin`, when set, is sent
    /// as `Origin`.
    pub fn connect(
        addr: SocketAddr,
        host: &str,
        path: &str,
        origin: Option<&str>,
        timeout: Duration,
        mut rng: Rng,
    ) -> Result<Client, ConnectError> {
        let deadline = Instant::now() + timeout;
        let other = |e: io::Error| ConnectError::Other(e.to_string());
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(other)?;
        stream.set_nodelay(true).map_err(other)?;
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);
        let key = base64(&nonce);
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nhost: {host}\r\nupgrade: websocket\r\n\
             connection: Upgrade\r\nsec-websocket-key: {key}\r\nsec-websocket-version: 13\r\n"
        );
        if let Some(origin) = origin {
            request.push_str(&format!("origin: {origin}\r\n"));
        }
        request.push_str("\r\n");
        let mut client = Client {
            stream,
            buf: Vec::new(),
            partial: None,
            rng,
        };
        client
            .stream
            .set_write_timeout(Some(timeout))
            .map_err(other)?;
        client.stream.write_all(request.as_bytes()).map_err(other)?;
        let head_end = loop {
            if let Some(i) = client.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if client.buf.len() > HEADER_CAP {
                return Err(ConnectError::Other(
                    "handshake headers exceed 16 KiB".into(),
                ));
            }
            if !client.fill(deadline).map_err(ConnectError::Other)? {
                return Err(ConnectError::Other("handshake timed out".into()));
            }
        };
        let head = std::str::from_utf8(&client.buf[..head_end])
            .map_err(|_| ConnectError::Other("non-UTF-8 handshake headers".into()))?
            .to_owned();
        client.buf.drain(..head_end);
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| ConnectError::Other("malformed status line".into()))?;
        if status != 101 {
            return Err(ConnectError::Status(status));
        }
        let header = |name: &str| {
            head.split("\r\n").skip(1).find_map(|line| {
                let (k, v) = line.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().to_owned())
            })
        };
        let upgrade = header("upgrade").unwrap_or_default();
        let connection = header("connection").unwrap_or_default();
        if !upgrade.eq_ignore_ascii_case("websocket")
            || !connection
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        {
            return Err(ConnectError::Other(
                "101 without Upgrade: websocket and Connection: upgrade".into(),
            ));
        }
        if header("sec-websocket-accept").as_deref() != Some(accept_key(&key).as_str()) {
            return Err(ConnectError::Other("wrong Sec-WebSocket-Accept".into()));
        }
        Ok(client)
    }

    /// Reads more bytes into the buffer until `deadline`: false on timeout.
    fn fill(&mut self, deadline: Instant) -> Result<bool, String> {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Ok(false);
        };
        self.stream
            .set_read_timeout(Some(left))
            .map_err(|e| e.to_string())?;
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err("connection closed by the server without a close frame".into()),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(false)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let frame = encode_frame(opcode, payload, &mut self.rng);
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("write failed: {e}"))
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.write_frame(1, text.as_bytes())
    }

    pub fn send_close(&mut self, code: u16, reason: &str) -> Result<(), String> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.write_frame(8, &payload)
    }

    /// The next message, waiting until `deadline`: `Ok(None)` on timeout.
    /// An error means the connection is unusable (closed without a close
    /// frame, an I/O error, or a protocol violation by the server).
    pub fn read(&mut self, deadline: Instant) -> Result<Option<Message>, String> {
        loop {
            while let Some(frame) = parse_frame(&self.buf)? {
                let payload = self.buf[frame.start..frame.end].to_vec();
                self.buf.drain(..frame.end);
                match frame.opcode {
                    9 => self.write_frame(10, &payload)?,
                    10 => {}
                    8 => {
                        let (code, reason) = match payload.len() {
                            0 => (1005, String::new()),
                            1 => return Err("close frame with a one-byte payload".into()),
                            _ => (
                                u16::from_be_bytes([payload[0], payload[1]]),
                                String::from_utf8(payload[2..].to_vec())
                                    .map_err(|_| "close reason is not UTF-8")?,
                            ),
                        };
                        return Ok(Some(Message::Close(code, reason)));
                    }
                    0 => {
                        let Some((_, data)) = self.partial.as_mut() else {
                            return Err("continuation frame without a message".into());
                        };
                        if data.len() + payload.len() > MAX_MESSAGE {
                            return Err(format!("message exceeds {MAX_MESSAGE} bytes"));
                        }
                        data.extend_from_slice(&payload);
                        if frame.fin
                            && let Some((opcode, data)) = self.partial.take()
                        {
                            return message(opcode, data).map(Some);
                        }
                    }
                    opcode => {
                        if self.partial.is_some() {
                            return Err("new message inside a fragmented one".into());
                        }
                        if frame.fin {
                            return message(opcode, payload).map(Some);
                        }
                        self.partial = Some((opcode, payload));
                    }
                }
            }
            if !self.fill(deadline)? {
                return Ok(None);
            }
        }
    }
}

fn message(opcode: u8, data: Vec<u8>) -> Result<Message, String> {
    match opcode {
        1 => String::from_utf8(data)
            .map(Message::Text)
            .map_err(|_| "text message is not UTF-8".into()),
        _ => Ok(Message::Binary(data)),
    }
}

/// The server side of the framing, for the tests' mock server: unmasks a
/// client frame at the start of `buf`.
#[cfg(test)]
pub fn parse_client_frame(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 2 || buf[1] & 0x80 == 0 {
        return None;
    }
    let opcode = buf[0] & 0x0f;
    let (len, mut at) = match buf[1] & 0x7f {
        126 => (
            usize::from(u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?])),
            4,
        ),
        127 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(buf.get(2..10)?);
            (u64::from_be_bytes(b) as usize, 10)
        }
        n => (usize::from(n), 2),
    };
    let mask = buf.get(at..at + 4)?.to_vec();
    at += 4;
    let payload = buf.get(at..at + len)?;
    Some((
        opcode,
        payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect(),
        at + len,
    ))
}

/// An unmasked server frame, for the tests' mock server.
#[cfg(test)]
pub fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= 0xffff => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_and_base64_match_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frames_round_trip_with_every_length_encoding() {
        let mut rng = Rng::new(7);
        for len in [0, 1, 125, 126, 127, 65_535, 65_536, 200_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let masked = encode_frame(2, &payload, &mut rng);
            let (opcode, unmasked, used) = parse_client_frame(&masked).unwrap();
            assert_eq!((opcode, used), (2, masked.len()));
            assert_eq!(unmasked, payload);
            let frame = server_frame(2, &payload);
            let parsed = parse_frame(&frame).unwrap().unwrap();
            assert_eq!(
                (parsed.fin, parsed.opcode, parsed.end),
                (true, 2, frame.len())
            );
            assert_eq!(&frame[parsed.start..parsed.end], payload.as_slice());
            assert_eq!(parse_frame(&frame[..frame.len() - 1]).unwrap(), None);
        }
    }

    #[test]
    fn server_frames_that_break_the_protocol_are_refused() {
        // Masked, reserved bits, fragmented control, oversized control,
        // unknown opcode, over the size cap.
        for bad in [
            vec![0x81, 0x80, 0, 0, 0, 0],
            vec![0xc1, 0x00],
            vec![0x09, 0x00],
            vec![0x89, 126, 0, 126],
            vec![0x83, 0x00],
            vec![0x82, 127, 0, 0, 0, 0, 0, 0x20, 0, 0],
        ] {
            assert!(parse_frame(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rng_streams_differ_by_seed_and_unit_is_in_range() {
        let (mut a, mut b) = (Rng::new(1), Rng::new(2));
        assert_ne!(a.next_u64(), b.next_u64());
        for _ in 0..1000 {
            let u = a.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }
}
