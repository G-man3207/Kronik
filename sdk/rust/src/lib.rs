//! Kronik's Rust SDK: write actors for the `kronik:actor` world.
//!
//! An actor type implements [`Actor`] and is exported with [`export!`]. The
//! crate is built as a `cdylib` for `wasm32-wasip2`, and the resulting
//! component is deployed with `kronik deploy`. This is the brief's counter:
//!
//! ```no_run
//! use kronik_sdk::prelude::*;
//!
//! struct Counter;
//!
//! impl Actor for Counter {
//!     fn describe() -> Manifest {
//!         Manifest::new("counter", 1).route(Route::post("/counter/{key}/increment"))
//!     }
//!
//!     fn handle(ctx: &mut Ctx, input: Input) -> Result<Output, HandlerError> {
//!         let n: u64 = ctx.state().get_json("n")?.unwrap_or(0) + 1;
//!         ctx.state().set_json("n", &n)?;
//!         Ok(Output::json(200, &serde_json::json!({ "n": n })))
//!     }
//! }
//!
//! kronik_sdk::export!(Counter);
//! ```
//!
//! Overriding [`Actor::handle`] means handling every input, including the
//! `migrate` turn that a new actor of a kind with a schema version above 0
//! runs first (the counter above counts it as an increment). Usually it is
//! simpler to keep the default `handle` and implement [`Actor::http`],
//! [`Actor::message`], [`Actor::timer`] and [`Actor::migrate`] as needed.
//!
//! # The turn
//!
//! Every input runs as one turn on a fresh instance. Memory never survives a
//! turn; state lives in [`Ctx::state`] and [`Ctx::sql`]. State writes, SQL
//! changes, [`Ctx::send`] and timers are buffered and take effect only if the
//! turn commits, which it does when `handle` returns `Ok`. An `Err`, a panic
//! or running out of fuel fails the turn and discards them.
//!
//! The API is synchronous: the host does the waiting. Time ([`Ctx::now`]),
//! randomness ([`Ctx::random`], and also `std`'s clocks and random numbers)
//! and the ids are deterministic and recorded, so a replay of the turn sees
//! the same values. Output on stdout and stderr becomes log events.
//!
//! Error messages from the SDK name a `kronik explain <topic>` command.
//!
//! # Tests
//!
//! On the host (not in Wasm), [`testkit::TestHost`] runs the project's
//! component in an in-memory node with a manual clock and stubbed HTTP.

// Lets the export macro and the generated bindings refer to this crate by
// name, from inside it as well as from the actor's crate.
extern crate self as kronik_sdk;

mod actor;
mod ctx;
mod error;
pub mod http;
mod sql;
mod types;

#[cfg(not(target_arch = "wasm32"))]
pub mod testkit;

#[doc(hidden)]
#[allow(
    missing_docs,
    unsafe_code,
    clippy::all,
    clippy::expect_used,
    clippy::unwrap_used
)]
pub mod bindings {
    //! The bindings that `wit-bindgen` generates from `wit/kronik-actor.wit`.
    wit_bindgen::generate!({
        world: "actor",
        path: "wit/kronik-actor.wit",
        pub_export_macro: true,
        export_macro_name: "__export_kronik_actor",
        default_bindings_module: "kronik_sdk::bindings",
    });
}

pub use actor::Actor;
pub use bindings::kronik::actor::log::Level;
pub use bindings::kronik::actor::messaging::CallError;
pub use bindings::kronik::actor::sql::{Rows, SqlError, SqlValue};
pub use bindings::kronik::actor::types::{
    ActorRef, BlobRef, HandlerError, Header, HttpBody, HttpRequest, HttpResponse, Incoming, Input,
    Manifest, Message, Output, Route, TimerFired,
};
pub use ctx::{Crypto, Ctx, Log, Random, Secrets, State, Timers};
pub use error::Error;
pub use http::{Http, Secret};
pub use sql::{FromSql, Row, Sql};

/// The names most actors need: `use kronik_sdk::prelude::*;`.
pub mod prelude {
    pub use crate::{
        Actor, ActorRef, Ctx, Error, HandlerError, HttpRequest, HttpResponse, Incoming, Input,
        Level, Manifest, Message, Output, Route, Row, Rows, Secret, SqlValue, TimerFired, params,
    };
}

/// Exports an [`Actor`] type as the component's `kronik:actor/handler`.
///
/// Use it once per component, at the crate root:
///
/// ```ignore
/// kronik_sdk::export!(Counter);
/// ```
#[macro_export]
macro_rules! export {
    ($actor:ty) => {
        const _: () = {
            struct KronikExport;

            impl $crate::bindings::exports::kronik::actor::handler::Guest for KronikExport {
                fn describe() -> $crate::Manifest {
                    <$actor as $crate::Actor>::describe()
                }

                fn handle(
                    input: $crate::Input,
                ) -> ::core::result::Result<$crate::Output, $crate::HandlerError> {
                    $crate::__private::handle::<$actor>(input)
                }
            }

    $crate::bindings::__export_kronik_actor!(KronikExport with_types_in $crate::bindings);
        };
    };
}

/// SQL parameters for [`Sql::query`] and [`Sql::execute`]:
/// `params![title, body]` is `&[SqlValue::from(title), SqlValue::from(body)]`.
#[macro_export]
macro_rules! params {
    () => {
        &[] as &[$crate::SqlValue]
    };
    ($($value:expr),+ $(,)?) => {
        &[$($crate::SqlValue::from($value)),+] as &[$crate::SqlValue]
    };
}

#[doc(hidden)]
pub mod __private {
    use crate::{Actor, Ctx, HandlerError, Input, Output};

    /// Runs one turn: the entry point that [`export!`](crate::export) wires up.
    pub fn handle<A: Actor>(input: Input) -> Result<Output, HandlerError> {
        A::handle(&mut Ctx::new(), input)
    }
}
