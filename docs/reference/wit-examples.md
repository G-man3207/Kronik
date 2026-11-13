# WIT usage examples

These are Rust **handler-context snippets** using bindings generated from the
actual current WIT, not a declaration repeated as an example. Start with the
[actor guide](../guides/actors.md) and the maintained
`tests/guests/test-actor`/SDK examples for a complete component. The
[WIT reference](wit.md) defines results, limits and commit behavior. Imports do
not grant capabilities. This page does not freeze the evolving IO ABI as 1.0.

## handler

The generated exported `Guest` trait supplies these two methods. A complete
component also invokes its generated export macro. For a key-value-only
example, the manifest's schema version is zero and the HTTP handler returns a
known body. Real applications must match their declared routes and inputs.

```rust
fn describe() -> Manifest {
    Manifest {
        kind: "counter".into(), schema_version: 0,
        routes: vec![Route { method: "GET".into(), pattern: "/counter/{key}".into() }],
        capabilities: vec![],
    }
}
fn handle(_input: Input) -> Result<Output, HandlerError> {
    Ok(Output::Reply(Message {
        name: "reply".into(), content_type: "text/plain".into(),
        body: b"known fixture response".to_vec(), blobs: vec![],
    }))
}
```

## state

Read-your-writes and deletion apply within the turn; nothing is published if
the handler fails. `set_for` explicitly chooses the subject rather than using
the current default. Use non-personal fixture data for this example.

```rust
state::set("counter:n", b"1");
let own_write = state::get("counter:n");
state::set_for(Some("fixture-user"), "counter:label", b"known label");
let ordered_keys = state::keys("counter:");
state::delete("counter:n");
```

## sql

Create the table only in the component's migrate input, before DML. In a
normal turn, bind values rather than interpolating input into SQL. Handle the
returned SQL error instead of turning a denied statement into a success.

```rust
let inserted = sql::execute(
    "INSERT INTO events(id, body) VALUES (?1, ?2)",
    &[sql::SqlValue::Integer(7), sql::SqlValue::Text("known event".into())],
);
let selected = sql::query(
    "SELECT body FROM events WHERE id = ?1", &[sql::SqlValue::Integer(7)],
);
```

## context

Logical time and the causal id repeat on identity replay. Random bytes are
seeded from this turn's recorded seed; do not use replayable randomness as an
unrecorded external authorization source.

```rust
let actor = context::self_ref();
let causal = context::causal_id();
let logical_ms = context::now_ms();
let deterministic_bytes = context::random_bytes(16);
```

## messaging

`send` is buffered until this turn commits. `call` runs the callee now and is
not atomic with the caller; handle its returned error and supply a real
compensation when the application's semantics require one.

```rust
let to = ActorRef { kind: "notes".into(), key: "fixture".into() };
let note = Message {
    name: "add".into(), content_type: "text/plain".into(),
    body: b"known note".to_vec(), blobs: vec![],
};
messaging::send(&to, &note);
let callee_result = messaging::call(&to, &note, None);
```

## timers

The delay is logical milliseconds. Canceling the newly scheduled timer sees
this turn's own pending operation; publication still depends on commit.

```rust
let tick = Message {
    name: "tick".into(), content_type: "text/plain".into(),
    body: vec![], blobs: vec![],
};
let id = timers::schedule(1000, &tick);
let was_pending = timers::cancel(id);
```

## http-client

The host inserts a granted secret at the actual effect boundary. An allowed
host and `secret:fixture-key` grant are separate prerequisites; a template
neither reveals the value to guest memory nor grants network access. Handle
`fetch-error`, including an unknown outcome, according to delivery semantics.

```rust
let result = http_client::fetch(&http_client::Request {
    method: "POST".into(), url: "https://api.example.com/events".into(),
    headers: vec![http_client::RequestHeader {
        name: "authorization".into(),
        value: http_client::HeaderValue::Secret(http_client::SecretTemplate {
            name: "fixture-key".into(), template: "Bearer {}".into(),
        }),
    }],
    body: HttpBody::Inline(b"known fixture event".to_vec()),
});
```

## crypto

Both calls need the actual secret grant. The signature call additionally
needs key material supported by the configured implementation; a short text
credential is not an Ed25519 signing key. Inspect `Err(denied/unsupported)`;
never replace it with a fake tag/signature.

```rust
let tag = crypto::hmac_sha256("fixture-key", b"known message");
let signature = crypto::sign_ed25519("fixture-signing-key", b"known message");
```

## secrets

Raw reveal is exceptional and requires `secret-reveal:fixture-key`. Do not
log, store or return the value merely to demonstrate the call. Prefer the
header/crypto handle paths above. A guest that obtains a value can transform
or disclose it; exact scrubbing is not a confinement boundary.

```rust
let raw_value = secrets::reveal("fixture-key").map_err(HandlerError::Failed)?;
```

## log

Log known, non-sensitive fields. Events receive the execution/causal context
from the host; do not include credentials or personal data in diagnostics.

```rust
log::emit(log::Level::Info, "fixture event handled",
          &[("result".into(), "accepted".into())]);
```

## privacy

Changing the default subject affects subsequent writes, not already-written
values. An explicit `state.set-for` overrides that default for its own write.
Correct subject tagging is an application responsibility.

```rust
privacy::set_subject(Some("fixture-user"));
let current = privacy::current_subject();
state::set("label", b"known fixture data");
```

## connections

These calls come from a component built for the world `actor-connections`
(M24), in a turn that holds the connection: its `open` input's, or one this
actor accepted earlier. `send`, `broadcast` and `close` are buffered until
the turn commits. `send-now` sends at once and needs a grant of
`connection:send-now`; after a crash it is never sent again, so handle
`outcome-unknown`.

```rust
let conn = event.connection.clone();
connections::send(&conn, &Frame::Text("welcome".into()));
let message = Frame::Event(SseEvent {
    event: "message".into(), id: "7".into(), data: "{\"seq\":7}".into(),
});
connections::broadcast(&members, &message);
match connections::send_now(&conn, &Frame::Text("tok 0".into())) {
    Ok(()) => {}
    Err(SendError::Closed) => { /* not sent: the client is gone or too slow */ }
    Err(SendError::OutcomeUnknown) => { /* after a crash: maybe sent, never resent */ }
    Err(SendError::Denied(reason)) => return Err(HandlerError::Failed(reason)),
}
connections::close(&conn, 1000, "bye");
```

## connection-handler

The generated exported `Guest` trait of `connection-handler` supplies these
three methods; each call is one turn. Accept or refuse in `open`; the client
gets its `101` or event stream after the open turn commits. Check `Origin`
in `open` when the app authenticates by cookie.

```rust
fn open(request: OpenRequest) -> Result<OpenReply, HandlerError> {
    if request.request.query.contains("deny=1") {
        return Ok(OpenReply::Refuse(HttpResponse {
            status: 403, headers: vec![], body: HttpBody::Inline(b"denied".to_vec()),
        }));
    }
    connections::send(&request.connection, &Frame::Text("welcome".into()));
    Ok(OpenReply::Accept(Accept {
        subprotocol: None, headers: vec![], subject: Some("fixture-user".into()),
    }))
}
fn frame(event: IncomingFrame) -> Result<(), HandlerError> {
    connections::send(&event.connection, &event.frame);
    Ok(())
}
fn close(event: Closed) -> Result<(), HandlerError> {
    state::delete(&format!("member/{}", event.connection));
    Ok(())
}
```

Future blob functions must gain their **actual** examples when the IO
interfaces are complete. `scripts/check-doc-surface.py` reads the current
WIT and will reject undocumented new functions; a baseline example page is
not evidence that a later ABI has been synchronized or exercised.
