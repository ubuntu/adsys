use thiserror::Error;

/// Our own error type
///
/// It's not good practice to return errors that are not from your own API
/// (unless they are from the std library, i.e. io or fmt errors).
#[non_exhaustive] // Blocks match expressions without wildcards (_) for this enum.
#[derive(Debug, Error)]
pub enum AdysMountError {
    MountError = 1,
    ParseError = 2,
}
impl std::fmt::Display for AdysMountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Process exited with error code: {:#?}", self)
    }
}
