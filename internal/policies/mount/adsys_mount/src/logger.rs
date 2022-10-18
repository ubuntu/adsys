use chrono::Utc;

use log::{Level, Log};
#[derive(Debug)]
pub struct Logger {}

impl Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "{} - {}: {}",
                Utc::now().format("%d/%m/%Y %H:%M:%S"),
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}
