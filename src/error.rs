use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetrcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("File permissions are too open (should be 0600 or stricter)")]
    InsecurePermissions,
}
