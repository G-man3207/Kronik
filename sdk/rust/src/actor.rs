use crate::{Ctx, HandlerError, HttpRequest, Incoming, Input, Manifest, Output, TimerFired};

/// An actor type: the code for one kind of actor.
///
/// Implement [`describe`](Actor::describe) and either the input methods you
/// need ([`http`](Actor::http), [`message`](Actor::message),
/// [`timer`](Actor::timer), [`migrate`](Actor::migrate)) or
/// [`handle`](Actor::handle) itself.
pub trait Actor {
    /// The kind's manifest: its name, schema version, HTTP routes and the
    /// capabilities it asks for.
    ///
    /// Runs at deploy time in an isolated turn without state or effects:
    /// using anything but [`Ctx::log`]'s host calls there traps.
    fn describe() -> Manifest;

    /// Handles one input. The default calls [`http`](Actor::http),
    /// [`message`](Actor::message), [`timer`](Actor::timer) or
    /// [`migrate`](Actor::migrate), depending on the input.
    fn handle(ctx: &mut Ctx, input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Http(request) => Self::http(ctx, request),
            Input::Message(incoming) => Self::message(ctx, incoming),
            Input::Timer(timer) => Self::timer(ctx, timer),
            Input::Migrate(from) => Self::migrate(ctx, from).map(|()| Output::None),
        }
    }

    /// Handles an HTTP request routed to this actor by one of the manifest's
    /// routes. The default rejects it.
    fn http(ctx: &mut Ctx, _request: HttpRequest) -> Result<Output, HandlerError> {
        Err(unhandled(ctx, "HTTP requests", "http", "actor"))
    }

    /// Handles a message from another actor or the operator. The default
    /// rejects it, which fails the turn and puts the message in the dead
    /// letters.
    fn message(ctx: &mut Ctx, _incoming: Incoming) -> Result<Output, HandlerError> {
        Err(unhandled(ctx, "messages", "message", "message"))
    }

    /// Handles a timer this actor scheduled. The default rejects it.
    fn timer(ctx: &mut Ctx, _timer: TimerFired) -> Result<Output, HandlerError> {
        Err(unhandled(ctx, "timers", "timer", "dead-letters"))
    }

    /// Migrates the actor's state from schema version `from` to the
    /// manifest's version.
    ///
    /// A new actor of a kind whose schema version is above 0 runs
    /// `migrate(0)` before its first input, and an existing actor runs
    /// `migrate(old)` after a deployment raises the schema version. SQL DDL
    /// (`CREATE TABLE`, `ALTER TABLE`, ...) is allowed only here, before the
    /// first statement that changes data. The default does nothing.
    fn migrate(_ctx: &mut Ctx, _from: u32) -> Result<(), HandlerError> {
        Ok(())
    }
}

fn unhandled(ctx: &Ctx, what: &str, method: &str, topic: &str) -> HandlerError {
    HandlerError::Rejected(format!(
        "actor type {} does not handle {what}: implement Actor::{method} (see `kronik explain {topic}`)",
        ctx.self_ref().kind,
    ))
}
