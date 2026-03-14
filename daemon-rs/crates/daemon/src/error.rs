use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("not implemented")]
    NotImplemented,
}
