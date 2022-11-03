use clap::Parser;
use lib::handle_user_mounts;
mod logger;

/// Arguments required to run this binary
#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path for the file containing the mounts for the user.
    mounts_file: String,
}

fn main() -> Result<(), lib::AdsysMountError> {
    let args = Args::parse();

    // Creates the logger and sets its level to Debug.
    if let Ok(()) = log::set_logger(&logger::Logger {}) {
        log::set_max_level(log::LevelFilter::Debug);
    }

    handle_user_mounts(&args.mounts_file)
}
