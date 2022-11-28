use lib::AdsysMountError;
mod logger;

fn main() -> Result<(), AdsysMountError> {
    if std::env::args().any(|p| &p == "--help") {
        print_help_msg();
        return Ok(());
    }

    let mut args = std::env::args();

    // Ensures that the binary is executed with exactly 2 arguments.
    if args.len() != 2 {
        print_usage_msg();
        return Err(AdsysMountError::ParseError);
    }

    // Ignores the first argument, which is the path of the executable.
    args.next();

    let mounts_file = match args.next() {
        Some(arg) => arg,
        None => {
            print_usage_msg();
            return Err(AdsysMountError::ParseError);
        }
    };

    // Creates the logger and sets its level to Debug.
    if let Ok(()) = log::set_logger(&logger::Logger {}) {
        log::set_max_level(log::LevelFilter::Debug);
    }

    lib::mount(&mounts_file)
}

fn print_help_msg() {
    print!(
        "\
Adsys helper binary to handle user mounts. This is not intended to be executed manually.

Usage:
    adsys_mount [filepath]
    

    filepath      Path to the file containing the shared directories to be mounted.
"
    );
}

fn print_usage_msg() {
    print!(
        "\
Usage:  
    adsys_mount [filepath]
"
    );
}
