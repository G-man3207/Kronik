//! One actor per key: POST /counter/<key>/increment counts the requests for
//! <key>. Every request runs as one turn; the state is recorded in the log.

use kronik_sdk::prelude::*;

struct Counter;

impl Actor for Counter {
    fn describe() -> Manifest {
        Manifest::new("counter", 1).route(Route::post("/counter/{key}/increment"))
    }

    fn http(ctx: &mut Ctx, _request: HttpRequest) -> Result<Output, HandlerError> {
        let n: u64 = ctx.state().get_json("n")?.unwrap_or(0) + 1;
        ctx.state().set_json("n", &n)?;
        Ok(Output::json(200, &serde_json::json!({ "n": n })))
    }
}

kronik_sdk::export!(Counter);
