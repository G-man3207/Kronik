//! Optional glibc PKCS#11 boundary; the daemon never links or loads a vendor module.
mod platform;
mod protocol;
mod token;

use std::process::ExitCode;

use protocol::{Error, Response};

fn run() -> Result<(), Error> {
    platform::protect()?;
    let output = platform::private_output()?;
    let result = (|| {
        if std::env::args_os().count() != 1 {
            return Err(Error::Protocol);
        }
        let input = platform::read_request()?;
        let request = protocol::parse(&input)?;
        let pin = platform::read_pin()?;
        let bytes = token::execute(&request, pin)?;
        let op = request.op;
        let response = Response::success(op, &bytes.nonce, &bytes.data);
        // Response borrows only zeroizing result strings, never the original secret request.
        drop(input);
        response.write(&output)
    })();
    if let Err(code) = result {
        Response::failure(code).write(&output)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    // No panic payload, provider message or protocol body is ever a diagnostic.
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
