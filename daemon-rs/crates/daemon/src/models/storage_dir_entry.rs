use std::{path::PathBuf, time::SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageDirEntry {
    pub path: PathBuf,
    pub is_file: bool,
    pub modified: Option<SystemTime>,
}