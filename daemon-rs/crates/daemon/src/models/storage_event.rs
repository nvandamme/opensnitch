use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageOperation {
    Read,
    Write,
    Delete,
    Scan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageEvent {
    pub domain: &'static str,
    pub operation: StorageOperation,
    pub path: PathBuf,
}