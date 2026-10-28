//! Spike D guest: a counter that charges an external payments service once
//! per increment.
//!
//! Per HTTP input it reads `n`, burns a seed-dependent amount of CPU (so the
//! host's fuel yields interleave turns), performs exactly one external effect
//! (`POST https://payments.sim/charge`), and only if that succeeds writes
//! `n + 1`, the logical time and a few random bytes. A failed effect fails the
//! turn, so nothing is written.

wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::types::{HandlerError, HttpBody, HttpResponse, Input, Manifest, Output, Route};
use kronik::actor::{context, http_client, state};

struct Counter;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Guest for Counter {
    fn describe() -> Manifest {
        Manifest {
            kind: "counter".to_string(),
            schema_version: 1,
            routes: vec![Route {
                method: "POST".to_string(),
                pattern: "/counter/{key}/increment".to_string(),
            }],
            capabilities: vec!["http:payments.sim".to_string()],
        }
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        let Input::Http(_req) = input else {
            return Err(HandlerError::Rejected(
                "only http input is supported".to_string(),
            ));
        };
        let n = state::get("n")
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        let now = context::now_ms();
        let rnd = context::random_bytes(4);

        // Seed-dependent CPU work: crosses several fuel-yield points.
        let rounds = 2_000 + u32::from(rnd[0]) * 40;
        let mut acc = u64::from(rnd[1]);
        for i in 0..rounds {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(u64::from(i));
        }

        let me = context::self_ref();
        let req = http_client::Request {
            method: "POST".to_string(),
            url: "https://payments.sim/charge".to_string(),
            headers: Vec::new(),
            body: HttpBody::Inline(format!("{}/{} n={n}", me.kind, me.key).into_bytes()),
        };
        match http_client::fetch(&req) {
            Ok(resp) if resp.status == 200 => {}
            Ok(resp) => {
                return Err(HandlerError::Failed(format!(
                    "payments status {}",
                    resp.status
                )));
            }
            Err(e) => return Err(HandlerError::Failed(format!("payments: {e:?}"))),
        }

        state::set("n", n.to_string().as_bytes());
        state::set("t", now.to_string().as_bytes());
        state::set("r", hex(&rnd).as_bytes());
        Ok(Output::Http(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: HttpBody::Inline(format!("n={n} t={now} acc={}", acc % 1000).into_bytes()),
        }))
    }
}

export!(Counter);
