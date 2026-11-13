// The room's manifest without the connection export (see lib.rs).

wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::types::{HandlerError, Input, Manifest, Output, Route};

struct Bare;

fn route(method: &str, pattern: &str) -> Route {
    Route {
        method: method.to_string(),
        pattern: pattern.to_string(),
    }
}

impl Guest for Bare {
    fn describe() -> Manifest {
        Manifest {
            kind: "room".to_string(),
            schema_version: 0,
            routes: vec![
                route("WEBSOCKET", "/room/{key}/ws"),
                route("GET", "/room/{key}/{op}"),
            ],
            capabilities: Vec::new(),
        }
    }

    fn handle(_input: Input) -> Result<Output, HandlerError> {
        Ok(Output::None)
    }
}

export!(Bare);
