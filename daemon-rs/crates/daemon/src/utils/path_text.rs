use std::{ffi::OsStr, path::Path};

pub(crate) fn lossy_os(value: impl AsRef<OsStr>) -> String {
    value.as_ref().to_string_lossy().into_owned()
}

pub(crate) fn lossy_path(value: impl AsRef<Path>) -> String {
    value.as_ref().to_string_lossy().into_owned()
}

pub(crate) fn file_name_lossy(path: &Path) -> Option<String> {
    path.file_name().map(lossy_os)
}
