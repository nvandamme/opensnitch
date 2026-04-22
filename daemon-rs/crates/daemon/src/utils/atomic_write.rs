use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::utils::time_nonce::unique_name;

pub(crate) fn sibling_temp_path_with_suffix(target_path: &Path, suffix: &str) -> PathBuf {
    let parent = target_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tempfile");
    parent.join(format!("{file_name}{suffix}"))
}

pub(crate) fn unique_sibling_temp_path(target_path: &Path, prefix: &str) -> PathBuf {
    sibling_temp_path_with_suffix(target_path, &format!(".{}", unique_name(prefix)))
}

/// Best-effort cleanup of a stale temp file from a previously interrupted write.
pub(crate) fn cleanup_stale_temp_file(temp_path: &Path) {
    if temp_path.exists() {
        let _ = std::fs::remove_file(temp_path);
    }
}

pub(crate) fn open_atomic_temp_file(temp_path: &Path, file_label: &str) -> Result<File> {
    cleanup_stale_temp_file(temp_path);
    File::create(temp_path)
        .with_context(|| format!("creating temp {file_label} file: {}", temp_path.display()))
}

/// Flush + fsync a temp file, atomically rename it into place, then fsync parent dir.
pub(crate) fn finalize_atomic_replace(
    mut temp_file: File,
    temp_path: &Path,
    target_path: &Path,
    file_label: &str,
) -> Result<()> {
    temp_file
        .flush()
        .with_context(|| format!("flushing temp {file_label} file: {}", temp_path.display()))?;
    temp_file
        .sync_all()
        .with_context(|| format!("fsync temp {file_label} file: {}", temp_path.display()))?;

    // Drop file handle before rename to avoid issues on some platforms.
    drop(temp_file);

    std::fs::rename(temp_path, target_path).with_context(|| {
        format!(
            "moving temp {file_label} file {} to {}",
            temp_path.display(),
            target_path.display()
        )
    })?;

    // fsync the parent directory to make the rename durable.
    if let Some(parent) = target_path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Write bytes to a temp file and atomically replace `target_path` from async callers.
pub(crate) fn write_bytes_atomic_sync(
    temp_path: &Path,
    target_path: &Path,
    data: &[u8],
    file_label: &str,
) -> Result<()> {
    let write_result = (|| -> Result<File> {
        let mut file = open_atomic_temp_file(temp_path, file_label)?;
        file.write_all(data)
            .with_context(|| format!("writing temp {file_label} file: {}", temp_path.display()))?;
        Ok(file)
    })();

    let file = match write_result {
        Ok(file) => file,
        Err(err) => {
            let _ = std::fs::remove_file(temp_path);
            return Err(err);
        }
    };

    if let Err(err) = finalize_atomic_replace(file, temp_path, target_path, file_label) {
        let _ = std::fs::remove_file(temp_path);
        return Err(err);
    }

    Ok(())
}

/// Write bytes to a temp file and atomically replace `target_path` from async callers.
pub(crate) async fn write_bytes_atomic_async(
    temp_path: &Path,
    target_path: &Path,
    data: &[u8],
    file_label: &str,
) -> Result<()> {
    let temp_path = temp_path.to_path_buf();
    let target_path = target_path.to_path_buf();
    let file_label = file_label.to_string();
    let data = data.to_vec();

    tokio::task::spawn_blocking(move || {
        write_bytes_atomic_sync(&temp_path, &target_path, &data, &file_label)
    })
    .await
    .context("joining atomic write task")?
}
