//! Borrow canonical hex from scrubbed input; decode escaped public identity strings only as needed.
use std::borrow::Cow;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SCHEMA: &str = "kronik.pkcs11/v1";
pub const LIMIT: usize = 4096;
pub const PURPOSE: &str = "kronik master v1";
pub const PROBE_PLAINTEXT: [u8; 32] = [0x4b; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    Protocol,
    Resource,
    Pin,
    Module,
    Token,
    Key,
    Attributes,
    Authentication,
    Provider,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe<'a> {
    pub nonce: &'a str,
    pub ciphertext: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request<'a> {
    pub schema: &'a str,
    pub op: &'a str,
    #[serde(borrow)]
    pub module: Cow<'a, str>,
    pub module_sha256: &'a str,
    #[serde(borrow)]
    pub manufacturer: Cow<'a, str>,
    #[serde(borrow)]
    pub model: Cow<'a, str>,
    #[serde(borrow)]
    pub serial: Cow<'a, str>,
    pub key_id: &'a str,
    #[serde(borrow)]
    pub key_version: Cow<'a, str>,
    #[serde(borrow)]
    pub purpose: Cow<'a, str>,
    #[serde(borrow)]
    pub probe: Option<Probe<'a>>,
    pub plaintext: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub ciphertext: Option<&'a str>,
}

fn text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.chars().all(|c| !c.is_control())
        && value.trim() == value
}

pub fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse(input: &[u8]) -> Result<Request<'_>, Error> {
    if input.is_empty() || input.len() > LIMIT {
        return Err(Error::Protocol);
    }
    let request: Request<'_> = serde_json::from_slice(input).map_err(|_| Error::Protocol)?;
    if request.schema != SCHEMA
        || request.purpose != PURPOSE
        || !text(&request.module, 1024)
        || !std::path::Path::new(request.module.as_ref()).is_absolute()
        || !is_hex(request.module_sha256, 32)
        || !text(&request.manufacturer, 32)
        || !text(&request.model, 16)
        || !text(&request.serial, 16)
        || !text(&request.key_version, 128)
        || request.key_id.is_empty()
        || request.key_id.len() > 128
        || request.key_id.len() % 2 != 0
        || !is_hex(request.key_id, request.key_id.len() / 2)
    {
        return Err(Error::Protocol);
    }
    let valid = match request.op {
        "enroll" => request.probe.is_none() && request.plaintext.is_none()
            && request.nonce.is_none() && request.ciphertext.is_none(),
        "wrap" => request.probe.as_ref().is_some_and(|p| is_hex(p.nonce, 12) && is_hex(p.ciphertext, 48))
            && request.plaintext.is_some_and(|p| is_hex(p, 32))
            && request.nonce.is_none() && request.ciphertext.is_none(),
        "unwrap" => request.probe.is_none() && request.plaintext.is_none()
            && request.nonce.is_some_and(|n| is_hex(n, 12))
            && request.ciphertext.is_some_and(|c| is_hex(c, 48)),
        _ => false,
    };
    if !valid {
        return Err(Error::Protocol);
    }
    Ok(request)
}

pub fn decode(value: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if value.len() % 2 != 0 || !is_hex(value, value.len() / 2) {
        return Err(Error::Protocol);
    }
    let mut bytes = Zeroizing::new(vec![0; value.len() / 2]);
    for (out, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(bytes)
}

pub fn encode(bytes: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    encoded
}

pub fn aad(request: &Request<'_>, enrollment: bool) -> Zeroizing<Vec<u8>> {
    // Module integrity is a trusted load gate, not key identity across module security upgrades.
    let fields = [request.manufacturer.as_ref(), request.model.as_ref(), request.serial.as_ref(),
        request.key_id, request.key_version.as_ref(), request.purpose.as_ref()];
    let domain: &[u8] = if enrollment {
        b"kronik.pkcs11/enrollment/v1\0"
    } else {
        b"kronik.pkcs11/seed/v1\0"
    };
    let size = domain.len() + fields.iter().map(|s| 4 + s.len()).sum::<usize>();
    let mut result = Zeroizing::new(Vec::with_capacity(size));
    result.extend_from_slice(domain);
    for field in fields {
        result.extend_from_slice(&(field.len() as u32).to_be_bytes());
        result.extend_from_slice(field.as_bytes());
    }
    result
}

pub fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(vec![0; limit + 1]);
    let mut used = 0;
    loop {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => {
                used += count;
                if used > limit {
                    return Err(Error::Protocol);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Protocol),
        }
    }
    bytes.truncate(used);
    Ok(bytes)
}

#[derive(Serialize)]
pub struct Response<'a> {
    schema: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<Error>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<ProbeResponse<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<&'a str>,
}

#[derive(Serialize)]
struct ProbeResponse<'a> {
    nonce: &'a str,
    ciphertext: &'a str,
}

impl<'a> Response<'a> {
    pub fn success(op: &str, nonce: &'a str, data: &'a str) -> Self {
        Self {
            schema: SCHEMA, ok: true, code: None,
            probe: (op == "enroll").then_some(ProbeResponse { nonce, ciphertext: data }),
            nonce: (op == "wrap").then_some(nonce),
            ciphertext: (op == "wrap").then_some(data),
            plaintext: (op == "unwrap").then_some(data),
        }
    }

    pub fn failure(code: Error) -> Self {
        Self { schema: SCHEMA, ok: false, code: Some(code), probe: None,
            nonce: None, ciphertext: None, plaintext: None }
    }

    pub fn write(&self, mut output: impl Write) -> Result<(), Error> {
        let mut bytes = Zeroizing::new([0u8; LIMIT]);
        let mut cursor = std::io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut cursor, self).map_err(|_| Error::Protocol)?;
        let len = cursor.position() as usize;
        output.write_all(&bytes[..len]).map_err(|_| Error::Protocol)?;
        output.flush().map_err(|_| Error::Protocol)
    }
}

#[cfg(test)]
mod tests;
