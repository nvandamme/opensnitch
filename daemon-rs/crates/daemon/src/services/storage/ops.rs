/// Low-level I/O helpers shared across `StorageService` method implementations.
///
/// Extracted from `storage.rs` per DESIGN_RULES §3 (API/orchestration surface
/// should not mix with low-level I/O helper logic).
use std::io;

/// Convert a `NotFound` I/O error into `Ok(None)`; propagate all other errors.
pub(super) fn option_if_not_found<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Return `true` if the operation succeeded, `false` if the path was not found.
/// Propagates all other errors.
pub(super) fn bool_if_not_found(result: io::Result<()>) -> io::Result<bool> {
    option_if_not_found(result).map(|maybe| maybe.is_some())
}

/// Return `true` if the path exists (metadata call succeeded), `false` if not found.
/// Propagates all other errors.
pub(super) fn exists_if_not_found<T>(result: io::Result<T>) -> io::Result<bool> {
    option_if_not_found(result).map(|maybe| maybe.is_some())
}
