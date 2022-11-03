use chrono::Utc;

use log::{Level, Log, Metadata, Record};
/// Logger used by adsys_mount to provide context about the mount process.
#[derive(Debug)]
pub struct Logger {}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        eprintln!(
            "{} - {}: {}",
            Utc::now().format("%d/%m/%Y %H:%M:%S"),
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}
