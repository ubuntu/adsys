use std::fmt::{Display, Formatter, Result};
use thiserror::Error;

/// Represents error codes used by adsys_mount.
#[derive(Debug, Error)]
pub enum AdsysMountError {
    MountError = 1,
    ArgError = 2,
}
impl Display for AdsysMountError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "Process exited with error code: {:#?}", self)
    }
}
