use time::{self, macros::format_description, OffsetDateTime};

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

        let fmt_time = OffsetDateTime::now_utc()
            .format(format_description!(
                "[day]/[month]/[year] [hour]:[minute]:[second]"
            ))
            .unwrap_or_else(|_| "00/00/0000 00:00:00".into());

        eprintln!("{} - {}: {}", fmt_time, record.level(), record.args());
    }

    fn flush(&self) {}
}
