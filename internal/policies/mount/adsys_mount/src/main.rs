use lib::AdsysMountError;
mod logger;

fn main() {
    let mut args = std::env::args();

    // Ensures that the binary is executed with exactly 2 arguments.
    if args.len() != 2 {
        print_usage_msg();
        std::process::exit(AdsysMountError::ArgError as i32);
    }

    // Creates the logger and sets its level to Debug.
    if let Ok(()) = log::set_logger(&logger::Logger {}) {
        log::set_max_level(log::LevelFilter::Debug);
    }

    // Ignores the first argument, which is the path of the executable.
    args.next();

    let arg = args.next().unwrap();
    if arg == "--help" {
        print_help_msg();
        return;
    }

    // We checked that there is another arg beside the executable, so the unwrap never panics.
    if let Err(e) = lib::mount(&arg) {
        std::process::exit(e as i32);
    }
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
