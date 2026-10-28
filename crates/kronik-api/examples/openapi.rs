//! Prints `docs/reference/openapi.json`, the OpenAPI description of `/v1`
//! that `GET /v1/openapi.json` serves:
//!
//! ```sh
//! cargo run -p kronik-api --example openapi > docs/reference/openapi.json
//! ```
//!
//! A test in `kronik_api::openapi` fails when the committed file differs.

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(&kronik_api::openapi::document_bytes())?;
    out.flush()
}
