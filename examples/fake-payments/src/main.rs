//! fake-payments: a small payments service for Kronik's examples, run as a
//! foreign actor. It charges and refunds without moving any money, honors
//! `Idempotency-Key` like a real payment provider, and keeps its state in
//! `<data-dir>/payments.json`.
//!
//! ```text
//! fake-payments [--listen ADDR] [--data-dir DIR]
//!
//! GET  /healthz              200 "ok"
//! POST /v1/charges           {"customer","invoice","amount","currency"} -> 201 charge
//! GET  /v1/charges/{id}      200 charge, 404
//! POST /v1/refunds           {"charge"} -> 201 refund, 404, 409
//! ```
//!
//! With `PAYMENTS_API_KEY` set, every `/v1/*` request needs
//! `Authorization: Bearer <key>`.

mod http;
mod json;
mod sha256;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use http::{ReadError, Request, Response};
use json::{Value, quote};

/// The largest request body accepted.
const MAX_BODY: usize = 64 * 1024;

/// How long an idle keep-alive connection is kept open.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The longest idempotency key accepted.
const MAX_KEY_LEN: usize = 255;

/// The longest customer or invoice id accepted.
const MAX_ID_LEN: usize = 255;

/// The state file's name in the data directory.
const STATE_FILE: &str = "payments.json";

const USAGE: &str = "usage: fake-payments [--listen ADDR] [--data-dir DIR]";

fn main() {
    let (listen, data_dir) = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("fake-payments: {msg}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let api_key = std::env::var("PAYMENTS_API_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    let app = match App::open(&data_dir, api_key) {
        Ok(app) => Arc::new(app),
        Err(msg) => {
            eprintln!("fake-payments: {msg}");
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fake-payments: cannot listen on {listen}: {e}");
            std::process::exit(1);
        }
    };
    let local = listener
        .local_addr()
        .map_or_else(|_| listen.clone(), |a| a.to_string());
    log(&format!(
        "fake-payments: listening on {local}, auth {}",
        if app.api_key.is_some() {
            "required"
        } else {
            "off"
        }
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app = Arc::clone(&app);
                let spawned = thread::Builder::new()
                    .name("conn".into())
                    .spawn(move || handle_connection(stream, &app));
                if let Err(e) = spawned {
                    log(&format!("fake-payments: cannot start a thread: {e}"));
                }
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                log(&format!("fake-payments: accept failed: {e}"));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<(String, PathBuf), String> {
    let mut listen = "0.0.0.0:8080".to_string();
    let mut data_dir = PathBuf::from("/data");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().ok_or("--listen needs a value")?,
            "--data-dir" => data_dir = args.next().ok_or("--data-dir needs a value")?.into(),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok((listen, data_dir))
}

/// Writes one line to stdout. A closed stdout must not kill the server.
fn log(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn handle_connection(stream: TcpStream, app: &App) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "?".to_string(), |a| a.to_string());
    let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    match stream.try_clone() {
        Ok(reader) => serve(reader, stream, &peer, app),
        Err(e) => log(&format!("{peer} cannot clone the socket: {e}")),
    }
}

/// Answers requests on one connection until it closes.
fn serve(read: impl Read, mut write: impl Write, peer: &str, app: &App) {
    let mut reader = BufReader::new(read);
    loop {
        let request = match http::read_request(&mut reader, MAX_BODY) {
            Ok(Some(r)) => r,
            Ok(None) | Err(ReadError::Io(_)) => return,
            Err(ReadError::Malformed(msg)) => {
                log(&format!("{peer} - - 400 {msg}"));
                let response = error(400, "invalid_request", &msg);
                let _ = http::write_response(&mut write, &response, false, false);
                return;
            }
        };
        let response = app.handle(&request);
        log(&format!(
            "{peer} {} {} {}",
            request.method, request.target, response.status
        ));
        let written = http::write_response(
            &mut write,
            &response,
            request.keep_alive,
            request.method == "HEAD",
        );
        if written.is_err() || !request.keep_alive {
            return;
        }
    }
}

/// An error answer: `{"error":{"code","message"}}`.
fn error(status: u16, code: &str, message: &str) -> Response {
    Response::json(
        status,
        format!(
            "{{\"error\":{{\"code\":{},\"message\":{}}}}}",
            quote(code),
            quote(message)
        ),
    )
}

/// A charge. `status` is `succeeded`, or `refunded` once refunded.
#[derive(Debug, Clone, PartialEq)]
struct Charge {
    id: String,
    customer: String,
    invoice: String,
    amount: i64,
    currency: String,
    status: String,
}

impl Charge {
    fn to_json(&self) -> String {
        format!(
            "{{\"id\":{},\"customer\":{},\"invoice\":{},\"amount\":{},\"currency\":{},\"status\":{}}}",
            quote(&self.id),
            quote(&self.customer),
            quote(&self.invoice),
            self.amount,
            quote(&self.currency),
            quote(&self.status)
        )
    }

    fn from_json(v: &Value) -> Option<Charge> {
        Some(Charge {
            id: v.get("id")?.as_str()?.to_string(),
            customer: v.get("customer")?.as_str()?.to_string(),
            invoice: v.get("invoice")?.as_str()?.to_string(),
            amount: v.get("amount")?.as_i64()?,
            currency: v.get("currency")?.as_str()?.to_string(),
            status: v.get("status")?.as_str()?.to_string(),
        })
    }
}

/// A refund of a whole charge.
#[derive(Debug, Clone, PartialEq)]
struct Refund {
    id: String,
    charge: String,
    amount: i64,
    status: String,
}

impl Refund {
    fn to_json(&self) -> String {
        format!(
            "{{\"id\":{},\"charge\":{},\"amount\":{},\"status\":{}}}",
            quote(&self.id),
            quote(&self.charge),
            self.amount,
            quote(&self.status)
        )
    }

    fn from_json(v: &Value) -> Option<Refund> {
        Some(Refund {
            id: v.get("id")?.as_str()?.to_string(),
            charge: v.get("charge")?.as_str()?.to_string(),
            amount: v.get("amount")?.as_i64()?,
            status: v.get("status")?.as_str()?.to_string(),
        })
    }
}

/// The saved outcome of the first request with an idempotency key.
#[derive(Debug, Clone, PartialEq)]
struct Record {
    /// SHA-256 of the method, path and body of that request.
    request_hash: String,
    status: u16,
    body: String,
}

/// Everything the service remembers.
#[derive(Debug, Default, PartialEq)]
struct State {
    /// The last number used for an id without an idempotency key.
    counter: u64,
    charges: BTreeMap<String, Charge>,
    refunds: BTreeMap<String, Refund>,
    /// By idempotency key.
    idempotency: BTreeMap<String, Record>,
}

impl State {
    /// The state file's content: compact JSON, keys sorted.
    fn to_json(&self) -> String {
        let charges: Vec<String> = self.charges.values().map(Charge::to_json).collect();
        let refunds: Vec<String> = self.refunds.values().map(Refund::to_json).collect();
        let records: Vec<String> = self
            .idempotency
            .iter()
            .map(|(key, r)| {
                format!(
                    "{{\"key\":{},\"request_hash\":{},\"status\":{},\"body\":{}}}",
                    quote(key),
                    quote(&r.request_hash),
                    r.status,
                    quote(&r.body)
                )
            })
            .collect();
        format!(
            "{{\"version\":1,\"counter\":{},\"charges\":[{}],\"refunds\":[{}],\"idempotency\":[{}]}}\n",
            self.counter,
            charges.join(","),
            refunds.join(","),
            records.join(",")
        )
    }

    fn from_json(text: &str) -> Result<State, String> {
        let v = json::parse(text)?;
        if v.get("version").and_then(Value::as_i64) != Some(1) {
            return Err("unknown version".into());
        }
        let list = |name: &str| {
            v.get(name)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{name} is missing"))
        };
        let mut state = State {
            counter: v
                .get("counter")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or("counter is missing")?,
            ..State::default()
        };
        for c in list("charges")? {
            let c = Charge::from_json(c).ok_or("bad charge")?;
            state.charges.insert(c.id.clone(), c);
        }
        for r in list("refunds")? {
            let r = Refund::from_json(r).ok_or("bad refund")?;
            state.refunds.insert(r.id.clone(), r);
        }
        for r in list("idempotency")? {
            let record = (|| {
                let key = r.get("key")?.as_str()?.to_string();
                let status = u16::try_from(r.get("status")?.as_i64()?).ok()?;
                Some((
                    key,
                    Record {
                        request_hash: r.get("request_hash")?.as_str()?.to_string(),
                        status,
                        body: r.get("body")?.as_str()?.to_string(),
                    },
                ))
            })()
            .ok_or("bad idempotency record")?;
            state.idempotency.insert(record.0, record.1);
        }
        Ok(state)
    }

    /// A new id: `<prefix>_` and the first 16 hex digits of the SHA-256 of
    /// the idempotency key, so a retried request gets the same id even if
    /// the state was lost; else (or if that id is taken) the next counter.
    fn new_id(&mut self, prefix: &str, key: Option<&str>) -> String {
        let taken = |s: &State, id: &str| s.charges.contains_key(id) || s.refunds.contains_key(id);
        if let Some(key) = key {
            let hex = sha256::hex(key.as_bytes());
            let id = format!("{prefix}_{}", &hex[..16]);
            if !taken(self, &id) {
                return id;
            }
        }
        loop {
            self.counter += 1;
            let id = format!("{prefix}_{:016x}", self.counter);
            if !taken(self, &id) {
                return id;
            }
        }
    }
}

/// What an operation decided.
struct Outcome {
    response: Response,
    /// Whether to save the answer under the idempotency key.
    save: bool,
    /// Whether the operation changed charges or refunds.
    changed: bool,
}

impl Outcome {
    /// An answer that is not saved, e.g. a validation error: the client may
    /// fix the request and retry with the same key.
    fn transient(response: Response) -> Self {
        Outcome {
            response,
            save: false,
            changed: false,
        }
    }

    /// A final answer, saved under the idempotency key if there is one.
    fn saved(response: Response, changed: bool) -> Self {
        Outcome {
            response,
            save: true,
            changed,
        }
    }
}

/// The service: state behind one lock, the API key, the state file.
struct App {
    state: Mutex<State>,
    api_key: Option<String>,
    /// Where state is saved; `None` keeps it in memory only.
    store: Option<PathBuf>,
}

impl App {
    /// Loads `<data_dir>/payments.json` if it exists. A missing or
    /// unwritable data directory gives a memory-only service (with a
    /// warning); an unreadable or corrupt state file is an error, so it is
    /// never overwritten.
    fn open(data_dir: &Path, api_key: Option<String>) -> Result<App, String> {
        let path = data_dir.join(STATE_FILE);
        let state = match fs::read_to_string(&path) {
            Ok(text) => State::from_json(&text)
                .map_err(|e| format!("{}: corrupt state file: {e}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        // Writing the state now proves the directory is writable.
        let store = match save(&path, &state) {
            Ok(()) => {
                log(&format!(
                    "fake-payments: state in {} ({} charges, {} refunds)",
                    path.display(),
                    state.charges.len(),
                    state.refunds.len()
                ));
                Some(path)
            }
            Err(e) => {
                log(&format!(
                    "fake-payments: warning: cannot write {}: {e}; keeping state in memory only",
                    path.display()
                ));
                None
            }
        };
        Ok(App {
            state: Mutex::new(state),
            api_key,
            store,
        })
    }

    /// Answers one request.
    fn handle(&self, request: &Request) -> Response {
        let path = request.path();
        let method = request.method.as_str();
        if path == "/healthz" {
            return match method {
                "GET" | "HEAD" => Response::text(200, "ok"),
                _ => method_not_allowed("GET, HEAD"),
            };
        }
        if !path.starts_with("/v1/") {
            return error(404, "not_found", "no such endpoint");
        }
        if !self.authorized(request) {
            let mut r = error(401, "unauthorized", "missing or wrong API key");
            r.headers.push(("www-authenticate".into(), "Bearer".into()));
            return r;
        }
        match path {
            "/v1/charges" if method == "POST" => self.idempotent(request, create_charge),
            "/v1/refunds" if method == "POST" => self.idempotent(request, create_refund),
            "/v1/charges" | "/v1/refunds" => method_not_allowed("POST"),
            _ => match path.strip_prefix("/v1/charges/") {
                Some(id) if !id.contains('/') => match method {
                    "GET" | "HEAD" => self.get_charge(id),
                    _ => method_not_allowed("GET, HEAD"),
                },
                _ => error(404, "not_found", "no such endpoint"),
            },
        }
    }

    fn authorized(&self, request: &Request) -> bool {
        let Some(key) = &self.api_key else {
            return true;
        };
        let Some(given) = request.header("authorization") else {
            return false;
        };
        match given.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => {
                constant_time_eq(token.trim().as_bytes(), key.as_bytes())
            }
            _ => false,
        }
    }

    fn get_charge(&self, id: &str) -> Response {
        let state = self.lock();
        match state.charges.get(id) {
            Some(c) => Response::json(200, c.to_json()),
            None => error(404, "not_found", &format!("no charge {id:?}")),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // With panic=abort a poisoned lock cannot happen; in tests take it.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `op` under the `Idempotency-Key` rules: the first request's
    /// answer is saved with a hash of the request; the same key and request
    /// replay it (`200` for a success, the saved status for an error, with
    /// `Idempotent-Replayed: true`); the same key with another request is
    /// `409`. State is saved after every change.
    fn idempotent(
        &self,
        request: &Request,
        op: fn(&mut State, &[u8], Option<&str>) -> Outcome,
    ) -> Response {
        let key = request.header("idempotency-key");
        if let Some(k) = key
            && (k.is_empty() || k.len() > MAX_KEY_LEN || !k.bytes().all(|b| b.is_ascii_graphic()))
        {
            return error(
                400,
                "invalid_request",
                "Idempotency-Key must be 1 to 255 visible ASCII characters",
            );
        }
        let mut hashed = format!("{} {}\n", request.method, request.path()).into_bytes();
        hashed.extend_from_slice(&request.body);
        let request_hash = sha256::hex(&hashed);

        let mut state = self.lock();
        if let Some(record) = key.and_then(|k| state.idempotency.get(k)) {
            if record.request_hash != request_hash {
                return error(
                    409,
                    "idempotency_key_reused",
                    "this Idempotency-Key was used with a different request",
                );
            }
            let status = if (200..300).contains(&record.status) {
                200
            } else {
                record.status
            };
            let mut r = Response::json(status, record.body.clone());
            r.headers
                .push(("idempotent-replayed".into(), "true".into()));
            return r;
        }
        let outcome = op(&mut state, &request.body, key);
        let mut changed = outcome.changed;
        if let (Some(k), true) = (key, outcome.save) {
            state.idempotency.insert(
                k.to_string(),
                Record {
                    request_hash,
                    status: outcome.response.status,
                    body: String::from_utf8_lossy(&outcome.response.body).into_owned(),
                },
            );
            changed = true;
        }
        if let (Some(path), true) = (&self.store, changed)
            && let Err(e) = save(path, &state)
        {
            log(&format!(
                "fake-payments: warning: cannot save {}: {e}",
                path.display()
            ));
        }
        outcome.response
    }
}

/// Writes the state file atomically: a temporary file next to it, synced,
/// then renamed over it.
fn save(path: &Path, state: &State) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(state.to_json().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Compares two byte strings in time independent of where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn method_not_allowed(allow: &str) -> Response {
    let mut r = error(405, "method_not_allowed", &format!("allowed: {allow}"));
    r.headers.push(("allow".into(), allow.into()));
    r
}

fn invalid(message: &str) -> Outcome {
    Outcome::transient(error(400, "invalid_request", message))
}

/// Parses a request body as a JSON object.
fn parse_object(body: &[u8]) -> Result<Value, Outcome> {
    let text = std::str::from_utf8(body).map_err(|_| invalid("the body is not UTF-8"))?;
    match json::parse(text) {
        Ok(v @ Value::Object(_)) => Ok(v),
        Ok(_) => Err(invalid("the body must be a JSON object")),
        Err(e) => Err(invalid(&format!("the body is not JSON: {e}"))),
    }
}

/// A required, non-empty string field of at most [`MAX_ID_LEN`] bytes.
fn id_field<'a>(v: &'a Value, name: &str) -> Result<&'a str, Outcome> {
    match v.get(name).and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.len() <= MAX_ID_LEN => Ok(s),
        _ => Err(invalid(&format!(
            "{name} must be a non-empty string of at most {MAX_ID_LEN} bytes"
        ))),
    }
}

/// `POST /v1/charges`.
fn create_charge(state: &mut State, body: &[u8], key: Option<&str>) -> Outcome {
    let fields = (|| {
        let v = parse_object(body)?;
        let customer = id_field(&v, "customer")?.to_string();
        let invoice = id_field(&v, "invoice")?.to_string();
        let amount = match v.get("amount").and_then(Value::as_i64) {
            Some(n) if n > 0 => n,
            _ => {
                return Err(invalid("amount must be a positive integer in minor units"));
            }
        };
        let currency = match v.get("currency").and_then(Value::as_str) {
            Some(c) if c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()) => c.to_string(),
            _ => return Err(invalid("currency must be 3 uppercase letters, e.g. EUR")),
        };
        Ok((customer, invoice, amount, currency))
    })();
    let (customer, invoice, amount, currency) = match fields {
        Ok(f) => f,
        Err(outcome) => return outcome,
    };
    if customer.starts_with("declined") {
        let declined = error(
            402,
            "card_declined",
            &format!("the card of customer {customer:?} was declined"),
        );
        return Outcome::saved(declined, false);
    }
    let charge = Charge {
        id: state.new_id("ch", key),
        customer,
        invoice,
        amount,
        currency,
        status: "succeeded".into(),
    };
    let response = Response::json(201, charge.to_json());
    state.charges.insert(charge.id.clone(), charge);
    Outcome::saved(response, true)
}

/// `POST /v1/refunds`: refunds a whole charge.
fn create_refund(state: &mut State, body: &[u8], key: Option<&str>) -> Outcome {
    let charge_id =
        match parse_object(body).and_then(|v| id_field(&v, "charge").map(str::to_string)) {
            Ok(id) => id,
            Err(outcome) => return outcome,
        };
    let amount = match state.charges.get(&charge_id) {
        None => {
            return Outcome::transient(error(
                404,
                "not_found",
                &format!("no charge {charge_id:?}"),
            ));
        }
        Some(c) if c.status == "refunded" => {
            return Outcome::transient(error(
                409,
                "charge_already_refunded",
                &format!("charge {charge_id:?} is already refunded"),
            ));
        }
        Some(c) => c.amount,
    };
    let refund = Refund {
        id: state.new_id("re", key),
        charge: charge_id.clone(),
        amount,
        status: "succeeded".into(),
    };
    if let Some(c) = state.charges.get_mut(&charge_id) {
        c.status = "refunded".into();
    }
    let response = Response::json(201, refund.to_json());
    state.refunds.insert(refund.id.clone(), refund);
    Outcome::saved(response, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const CHARGE: &str = r#"{"customer":"acme","invoice":"inv-1","amount":12500,"currency":"EUR"}"#;

    fn app(api_key: Option<&str>) -> App {
        App {
            state: Mutex::new(State::default()),
            api_key: api_key.map(str::to_string),
            store: None,
        }
    }

    fn request(method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: method.into(),
            target: target.into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
            keep_alive: true,
        }
    }

    fn call(
        app: &App,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, Value, Response) {
        let r = app.handle(&request(method, target, headers, body));
        let v = json::parse(&String::from_utf8_lossy(&r.body)).unwrap_or(Value::Null);
        (r.status, v, r)
    }

    fn code(v: &Value) -> Option<&str> {
        v.get("error")?.get("code")?.as_str()
    }

    fn replayed(r: &Response) -> bool {
        r.headers
            .iter()
            .any(|(n, v)| n == "idempotent-replayed" && v == "true")
    }

    #[test]
    fn creates_and_reads_a_charge() {
        let app = app(None);
        let (status, v, r) = call(&app, "POST", "/v1/charges", &[], CHARGE);
        assert_eq!(status, 201);
        assert!(!replayed(&r));
        let id = v.get("id").and_then(Value::as_str).unwrap().to_string();
        assert_eq!(id, "ch_0000000000000001");
        assert_eq!(v.get("amount").and_then(Value::as_i64), Some(12500));
        assert_eq!(v.get("status").and_then(Value::as_str), Some("succeeded"));
        let (status, got, _) = call(&app, "GET", &format!("/v1/charges/{id}"), &[], "");
        assert_eq!((status, got), (200, v));
        let (status, v, _) = call(&app, "GET", "/v1/charges/ch_nope", &[], "");
        assert_eq!((status, code(&v)), (404, Some("not_found")));
        // Without a key, the same request makes a new charge.
        let (_, v, _) = call(&app, "POST", "/v1/charges", &[], CHARGE);
        assert_eq!(
            v.get("id").and_then(Value::as_str),
            Some("ch_0000000000000002")
        );
    }

    #[test]
    fn validation() {
        let app = app(None);
        for body in [
            "",
            "[]",
            "{",
            r#"{"invoice":"i","amount":1,"currency":"EUR"}"#,
            r#"{"customer":"","invoice":"i","amount":1,"currency":"EUR"}"#,
            r#"{"customer":"a","amount":1,"currency":"EUR"}"#,
            r#"{"customer":"a","invoice":"i","amount":0,"currency":"EUR"}"#,
            r#"{"customer":"a","invoice":"i","amount":-5,"currency":"EUR"}"#,
            r#"{"customer":"a","invoice":"i","amount":1.5,"currency":"EUR"}"#,
            r#"{"customer":"a","invoice":"i","amount":"1","currency":"EUR"}"#,
            r#"{"customer":"a","invoice":"i","amount":1,"currency":"eur"}"#,
            r#"{"customer":"a","invoice":"i","amount":1,"currency":"EURO"}"#,
            r#"{"customer":"a","invoice":"i","amount":1}"#,
        ] {
            let (status, v, _) = call(&app, "POST", "/v1/charges", &[], body);
            assert_eq!((status, code(&v)), (400, Some("invalid_request")), "{body}");
            assert!(v.get("error").and_then(|e| e.get("message")).is_some());
        }
        // A rejected request is not saved: the key can be used again.
        let key = [("idempotency-key", "k")];
        let (status, _, _) = call(&app, "POST", "/v1/charges", &key, "{}");
        assert_eq!(status, 400);
        let (status, _, _) = call(&app, "POST", "/v1/charges", &key, CHARGE);
        assert_eq!(status, 201);
        let bad_key = [("idempotency-key", "a b")];
        assert_eq!(call(&app, "POST", "/v1/charges", &bad_key, CHARGE).0, 400);
    }

    #[test]
    fn idempotency_replays_and_rejects_reuse() {
        let app = app(None);
        let key = [("idempotency-key", "key-1")];
        let (status, first, r) = call(&app, "POST", "/v1/charges", &key, CHARGE);
        assert_eq!(status, 201);
        assert!(!replayed(&r));
        let expected_id = format!("ch_{}", &sha256::hex(b"key-1")[..16]);
        assert_eq!(
            first.get("id").and_then(Value::as_str),
            Some(expected_id.as_str())
        );

        let (status, again, r) = call(&app, "POST", "/v1/charges", &key, CHARGE);
        assert_eq!((status, &again), (200, &first));
        assert!(replayed(&r));
        assert_eq!(app.lock().charges.len(), 1);

        let other = CHARGE.replace("12500", "12501");
        let (status, v, r) = call(&app, "POST", "/v1/charges", &key, &other);
        assert_eq!((status, code(&v)), (409, Some("idempotency_key_reused")));
        assert!(!replayed(&r));
        // The same key on another endpoint is another request too.
        let refund = format!("{{\"charge\":\"{expected_id}\"}}");
        let (status, _, _) = call(&app, "POST", "/v1/refunds", &key, &refund);
        assert_eq!(status, 409);
    }

    #[test]
    fn declines_are_saved_and_replayed() {
        let app = app(None);
        let body = CHARGE.replace("acme", "declined-acme");
        let key = [("idempotency-key", "d")];
        let (status, v, _) = call(&app, "POST", "/v1/charges", &key, &body);
        assert_eq!((status, code(&v)), (402, Some("card_declined")));
        let (status, again, r) = call(&app, "POST", "/v1/charges", &key, &body);
        assert_eq!((status, &again), (402, &v));
        assert!(replayed(&r));
        assert!(app.lock().charges.is_empty());
        let (status, _, _) = call(&app, "POST", "/v1/charges", &key, CHARGE);
        assert_eq!(status, 409);
    }

    #[test]
    fn refunds() {
        let app = app(None);
        let (_, charge, _) = call(&app, "POST", "/v1/charges", &[], CHARGE);
        let id = charge.get("id").and_then(Value::as_str).unwrap();
        let body = format!("{{\"charge\":\"{id}\"}}");
        let key = [("idempotency-key", "r-1")];
        let (status, refund, _) = call(&app, "POST", "/v1/refunds", &key, &body);
        assert_eq!(status, 201);
        assert_eq!(refund.get("charge").and_then(Value::as_str), Some(id));
        assert_eq!(refund.get("amount").and_then(Value::as_i64), Some(12500));
        assert_eq!(
            refund.get("status").and_then(Value::as_str),
            Some("succeeded")
        );
        assert!(
            refund
                .get("id")
                .and_then(Value::as_str)
                .unwrap()
                .starts_with("re_")
        );
        // A retried compensation replays.
        let (status, again, r) = call(&app, "POST", "/v1/refunds", &key, &body);
        assert_eq!((status, &again), (200, &refund));
        assert!(replayed(&r));
        // A second refund under another key conflicts.
        let (status, v, _) = call(&app, "POST", "/v1/refunds", &[], &body);
        assert_eq!((status, code(&v)), (409, Some("charge_already_refunded")));
        let (_, got, _) = call(&app, "GET", &format!("/v1/charges/{id}"), &[], "");
        assert_eq!(got.get("status").and_then(Value::as_str), Some("refunded"));
        let (status, v, _) = call(&app, "POST", "/v1/refunds", &[], r#"{"charge":"ch_x"}"#);
        assert_eq!((status, code(&v)), (404, Some("not_found")));
        let (status, _, _) = call(&app, "POST", "/v1/refunds", &[], r#"{"charge":1}"#);
        assert_eq!(status, 400);
    }

    #[test]
    fn auth() {
        let app = app(Some("s3cret"));
        for headers in [
            &[][..],
            &[("authorization", "Bearer wrong")][..],
            &[("authorization", "Basic s3cret")][..],
            &[("authorization", "s3cret")][..],
        ] {
            let (status, v, _) = call(&app, "POST", "/v1/charges", headers, CHARGE);
            assert_eq!((status, code(&v)), (401, Some("unauthorized")));
            assert_eq!(call(&app, "GET", "/v1/charges/x", headers, "").0, 401);
        }
        let ok = [("authorization", "bearer s3cret")];
        assert_eq!(call(&app, "POST", "/v1/charges", &ok, CHARGE).0, 201);
        // /healthz needs no key.
        assert_eq!(call(&app, "GET", "/healthz", &[], "").0, 200);
    }

    #[test]
    fn routing() {
        let app = app(None);
        assert_eq!(call(&app, "GET", "/v1/charges", &[], "").0, 405);
        assert_eq!(call(&app, "DELETE", "/v1/charges/x", &[], "").0, 405);
        assert_eq!(call(&app, "GET", "/v1/other", &[], "").0, 404);
        assert_eq!(call(&app, "GET", "/v1/charges/a/b", &[], "").0, 404);
        assert_eq!(call(&app, "GET", "/", &[], "").0, 404);
    }

    #[test]
    fn state_is_persisted_and_reloaded() {
        let dir = std::env::temp_dir().join(format!("fake-payments-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let first = App::open(&dir, None).unwrap();
        assert!(first.store.is_some());
        let key = [("idempotency-key", "persist")];
        let (_, charge, _) = call(&first, "POST", "/v1/charges", &key, CHARGE);
        // A customer id with an escaped quote exercises escaping in the file.
        let declined = CHARGE.replace("acme", r#"declined\"x"#);
        call(
            &first,
            "POST",
            "/v1/charges",
            &[("idempotency-key", "dd")],
            &declined,
        );
        drop(first);
        assert!(!dir.join("payments.json.tmp").exists());

        let second = App::open(&dir, None).unwrap();
        let (status, again, r) = call(&second, "POST", "/v1/charges", &key, CHARGE);
        assert_eq!((status, &again), (200, &charge));
        assert!(replayed(&r));
        assert_eq!(
            call(
                &second,
                "POST",
                "/v1/charges",
                &[("idempotency-key", "dd")],
                &declined
            )
            .0,
            402
        );
        let saved = fs::read_to_string(dir.join("payments.json")).unwrap();
        assert_eq!(State::from_json(&saved).unwrap(), *second.lock());

        fs::write(dir.join("payments.json"), "{not json").unwrap();
        assert!(App::open(&dir, None).is_err());
        fs::remove_dir_all(&dir).unwrap();

        // A missing data directory gives a memory-only service.
        let memory = App::open(&dir.join("missing"), None).unwrap();
        assert!(memory.store.is_none());
        assert_eq!(call(&memory, "POST", "/v1/charges", &[], CHARGE).0, 201);
    }

    #[test]
    fn keep_alive_and_malformed_requests() {
        let app = app(None);
        let raw = format!(
            "GET /healthz HTTP/1.1\r\n\r\nPOST /v1/charges HTTP/1.1\r\nContent-Length: {}\r\n\r\n{CHARGE}BAD\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n",
            CHARGE.len()
        );
        let mut out = Vec::new();
        serve(Cursor::new(raw.into_bytes()), &mut out, "test", &app);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("HTTP/1.1 ").count(), 3, "{out}");
        assert!(out.contains("HTTP/1.1 201 Created"));
        assert!(out.contains("HTTP/1.1 400 Bad Request\r\ncontent-length"));
        assert!(out.contains("connection: close"));
    }
}
