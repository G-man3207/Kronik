//! counter-rs: the smallest possible actor, the brief's counter.
//!
//! Every actor `counter/<key>` keeps a number `n` in its state.
//!
//! - `POST /counter/{key}/increment` adds one and returns `{"n": n}`.
//! - `GET /counter/{key}` returns `{"n": n}` without changing it.
//! - Any message, for example `kronik send counter/alice increment`, adds
//!   one and replies `{"n": n}`, like the brief's example.
//!
//! The kind has schema version 1, so a new actor first runs `migrate(0)`;
//! the counter has no schema, so that turn changes nothing. The `step2`
//! build adds 2 instead of 1, a changed behavior for the M3 tests.

use kronik_sdk::prelude::*;

struct Counter;

/// How much an increment adds.
const STEP: u64 = if cfg!(feature = "step2") { 2 } else { 1 };

impl Actor for Counter {
    fn describe() -> Manifest {
        Manifest::new("counter", 1)
            .route(Route::post("/counter/{key}/increment"))
            .route(Route::get("/counter/{key}"))
    }

    fn handle(ctx: &mut Ctx, input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Migrate(_) => Ok(Output::none()),
            Input::Http(request) if request.method == "GET" => {
                let n: u64 = ctx.state().get_json("n")?.unwrap_or(0);
                Ok(Output::json(200, &serde_json::json!({ "n": n })))
            }
            _ => {
                let n: u64 = ctx.state().get_json("n")?.unwrap_or(0) + STEP;
                ctx.state().set_json("n", &n)?;
                Ok(Output::json(200, &serde_json::json!({ "n": n })))
            }
        }
    }
}

kronik_sdk::export!(Counter);
