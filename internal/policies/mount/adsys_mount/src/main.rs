use lib::AdsysMountError;
mod logger;

fn main() -> Result<(), AdsysMountError> {
    if std::env::args().any(|p| &p == "--help") {
        print_help_msg();
        return Ok(());
    }

    let mut args = std::env::args();

    // Ignores the first argument, which is the path of the executable.
    args.next();

    let mounts_file = match args.next() {
        Some(arg) => arg,
        None => {
            print_invalid_msg();
            return Ok(());
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
Adsys helper binary to handle user mounts. This is not intended to be used manually.

Usage:
    adsys_mount [filepath]
    

    filepath      Path to the file containing the shared directories to be mounted.
"
    );
}

fn print_invalid_msg() {
    print!(
        "\
Usage:  
    adsys_mount [filepath]
"
    );
}
