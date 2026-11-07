use std::fs::File;
use std::io;

fn main() {
    let result = (|| -> io::Result<()> {
        if std::process::id() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "guest init must be PID1",
            ));
        }
        if let Some(note) = kronik_guest_init::ignored_arguments(std::env::args_os()) {
            eprintln!("kronik-guest-init: {note}");
        }
        let config = kronik_guest_init::GuestConfig::parse(File::open("/config.json")?)?;
        kronik_guest_init::run_guest(config)
    })();
    if let Err(error) = result {
        eprintln!("kronik-guest-init: {error}");
    }
    if std::process::id() == 1
        && let Err(error) = kronik_guest_init::power_off()
    {
        eprintln!("kronik-guest-init: ending the VM failed: {error}");
    }
    std::process::exit(1);
}
