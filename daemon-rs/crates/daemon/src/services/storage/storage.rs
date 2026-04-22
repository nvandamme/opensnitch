use std::{
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::SystemTime,
};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use super::event_bus::StorageEventBus;

pub(crate) use super::event_bus::StorageEventSubscription;
pub(crate) use crate::models::storage_dir_entry::StorageDirEntry;
pub(crate) use crate::models::storage_event::{StorageEvent, StorageOperation};

use crate::utils::atomic_write::{write_bytes_atomic_async, write_bytes_atomic_sync};

#[derive(Clone, Debug)]
pub(crate) struct StorageService {
    events: StorageEventBus,
}

#[allow(dead_code)]
impl StorageService {
    fn option_if_not_found<T>(result: io::Result<T>) -> io::Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn bool_if_not_found(result: io::Result<()>) -> io::Result<bool> {
        Self::option_if_not_found(result).map(|maybe| maybe.is_some())
    }

    fn exists_if_not_found<T>(result: io::Result<T>) -> io::Result<bool> {
        Self::option_if_not_found(result).map(|maybe| maybe.is_some())
    }

    pub(crate) fn new() -> Self {
        Self {
            events: StorageEventBus::new(),
        }
    }

    pub(crate) fn global() -> Self {
        static GLOBAL: OnceLock<StorageService> = OnceLock::new();
        GLOBAL.get_or_init(Self::new).clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn subscribe_events(&self) -> StorageEventSubscription {
        self.events.subscribe()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn subscribe_events_for_path(&self, path: &Path) -> StorageEventSubscription {
        self.events.subscribe_for_path(path)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn subscribe_events_for_prefix(&self, path: &Path) -> StorageEventSubscription {
        self.events.subscribe_for_prefix(path)
    }

    pub(crate) async fn read_to_string(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        tokio::fs::read_to_string(path).await
    }

    pub(crate) async fn read_to_string_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        let contents = tokio::fs::read_to_string(path).await?;
        self.events.emit_read(domain, path);
        Ok(contents)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn read_to_string_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<String>> {
        Self::option_if_not_found(tokio::fs::read_to_string(path).await)
    }

    pub(crate) async fn read_to_string_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<String>> {
        let maybe_contents = Self::option_if_not_found(tokio::fs::read_to_string(path).await)?;
        if maybe_contents.is_some() {
            self.events.emit_read(domain, path);
        }
        Ok(maybe_contents)
    }

    pub(crate) fn read_to_string_sync(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    pub(crate) fn read_to_string_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        let contents = std::fs::read_to_string(path)?;
        self.events.emit_read(domain, path);
        Ok(contents)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_bytes_sync(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    pub(crate) fn read_bytes_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<u8>> {
        let contents = std::fs::read(path)?;
        self.events.emit_read(domain, path);
        Ok(contents)
    }

    pub(crate) async fn read_json<T>(&self, domain: &'static str, path: &Path) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let raw = self
            .read_to_string(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing JSON file {}", path.display()))
    }

    pub(crate) async fn read_json_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let raw = self
            .read_to_string_and_notify(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing JSON file {}", path.display()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn read_json_if_exists<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let Some(raw) = self
            .read_to_string_if_exists(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?
        else {
            return Ok(None);
        };

        let parsed = serde_json::from_str(&raw)
            .with_context(|| format!("parsing JSON file {}", path.display()))?;
        Ok(Some(parsed))
    }

    pub(crate) async fn read_json_if_exists_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let Some(raw) = self
            .read_to_string_if_exists_and_notify(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?
        else {
            return Ok(None);
        };

        let parsed = serde_json::from_str(&raw)
            .with_context(|| format!("parsing JSON file {}", path.display()))?;
        Ok(Some(parsed))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_json_sync<T>(&self, domain: &'static str, path: &Path) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let raw = self
            .read_to_string_sync(domain, path)
            .with_context(|| format!("reading file {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing JSON file {}", path.display()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn remove_file_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        Self::bool_if_not_found(tokio::fs::remove_file(path).await)
    }

    pub(crate) async fn remove_file_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let deleted = Self::bool_if_not_found(tokio::fs::remove_file(path).await)?;
        if deleted {
            self.events.emit_delete(domain, path);
        }
        Ok(deleted)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn remove_path_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let Some(metadata) = Self::option_if_not_found(tokio::fs::metadata(path).await)? else {
            return Ok(false);
        };

        if metadata.is_dir() {
            tokio::fs::remove_dir_all(path).await?;
        } else {
            tokio::fs::remove_file(path).await?;
        }
        Ok(true)
    }

    pub(crate) async fn remove_path_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let Some(metadata) = Self::option_if_not_found(tokio::fs::metadata(path).await)? else {
            return Ok(false);
        };

        if metadata.is_dir() {
            tokio::fs::remove_dir_all(path).await?;
        } else {
            tokio::fs::remove_file(path).await?;
        }
        self.events.emit_delete(domain, path);
        Ok(true)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn create_dir_all(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<()> {
        tokio::fs::create_dir_all(path).await
    }

    pub(crate) async fn create_dir_all_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<()> {
        tokio::fs::create_dir_all(path).await?;
        self.events.emit_write(domain, path);
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn create_dir_all_sync(&self, _domain: &'static str, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    pub(crate) fn create_dir_all_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        self.events.emit_write(domain, path);
        Ok(())
    }

    pub(crate) async fn path_exists(&self, _domain: &'static str, path: &Path) -> io::Result<bool> {
        Self::exists_if_not_found(tokio::fs::metadata(path).await)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn path_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let exists = Self::exists_if_not_found(tokio::fs::metadata(path).await)?;
        if exists {
            self.events.emit_read(domain, path);
        }
        Ok(exists)
    }

    pub(crate) fn path_exists_sync(&self, _domain: &'static str, path: &Path) -> io::Result<bool> {
        Self::exists_if_not_found(std::fs::metadata(path))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn path_exists_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let exists = Self::exists_if_not_found(std::fs::metadata(path))?;
        if exists {
            self.events.emit_read(domain, path);
        }
        Ok(exists)
    }

    pub(crate) async fn modified_time_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<SystemTime>> {
        let maybe_metadata = Self::option_if_not_found(tokio::fs::metadata(path).await)?;
        Ok(maybe_metadata.and_then(|metadata| metadata.modified().ok()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn modified_time_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<SystemTime>> {
        let maybe_metadata = Self::option_if_not_found(tokio::fs::metadata(path).await)?;
        if let Some(metadata) = maybe_metadata {
            self.events.emit_read(domain, path);
            return Ok(metadata.modified().ok());
        }
        Ok(None)
    }

    pub(crate) async fn list_dir(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<PathBuf>> {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            paths.push(entry.path());
        }
        Ok(paths)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn list_dir_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<PathBuf>> {
        let paths = self.list_dir(domain, path).await?;
        self.events.emit(domain, StorageOperation::Scan, path);
        Ok(paths)
    }

    pub(crate) async fn list_dir_with_metadata(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<StorageDirEntry>> {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut items = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            items.push(StorageDirEntry {
                path: entry.path(),
                is_file: metadata.is_file(),
                modified: metadata.modified().ok(),
            });
        }
        Ok(items)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn list_dir_with_metadata_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<StorageDirEntry>> {
        let items = self.list_dir_with_metadata(domain, path).await?;
        self.events.emit(domain, StorageOperation::Scan, path);
        Ok(items)
    }

    pub(crate) async fn read_link_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<PathBuf>> {
        Self::option_if_not_found(tokio::fs::read_link(path).await)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn read_link_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<PathBuf>> {
        let maybe_target = Self::option_if_not_found(tokio::fs::read_link(path).await)?;
        if maybe_target.is_some() {
            self.events.emit_read(domain, path);
        }
        Ok(maybe_target)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn create_symlink(
        &self,
        _domain: &'static str,
        target: &Path,
        link_path: &Path,
    ) -> io::Result<()> {
        let target = target.to_path_buf();
        let link_path = link_path.to_path_buf();
        tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(&target, &link_path))
            .await
            .map_err(|err| io::Error::other(format!("joining symlink task: {err}")))??;
        Ok(())
    }

    pub(crate) async fn create_symlink_and_notify(
        &self,
        domain: &'static str,
        target: &Path,
        link_path: &Path,
    ) -> io::Result<()> {
        let target = target.to_path_buf();
        let link_path = link_path.to_path_buf();
        let emitted_path = link_path.clone();
        tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(&target, &link_path))
            .await
            .map_err(|err| io::Error::other(format!("joining symlink task: {err}")))??;
        self.events.emit_write(domain, emitted_path.as_path());
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn write_bytes_atomic(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        write_bytes_atomic_async(temp_path, path, bytes, domain).await
    }

    pub(crate) async fn write_bytes_atomic_and_notify(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        write_bytes_atomic_async(temp_path, path, bytes, domain).await?;
        self.events.emit_write(domain, path);
        Ok(())
    }

    /// Create parent directories if needed, then write `bytes` to `path`
    /// atomically via a sibling `.tmp` file, emitting storage events for both.
    pub(crate) async fn write_bytes_to_path_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            self.create_dir_all_and_notify(domain, parent).await?;
        }
        let temp_path = crate::utils::atomic_write::sibling_temp_path_with_suffix(path, ".tmp");
        self.write_bytes_atomic_and_notify(domain, &temp_path, path, bytes)
            .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn write_bytes_atomic_sync(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        write_bytes_atomic_sync(temp_path, path, bytes, domain)
    }

    pub(crate) fn write_bytes_atomic_sync_and_notify(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        write_bytes_atomic_sync(temp_path, path, bytes, domain)?;
        self.events.emit_write(domain, path);
        Ok(())
    }

    pub(crate) fn emit_scan(&self, domain: &'static str, path: &Path) {
        self.events.emit(domain, StorageOperation::Scan, path);
    }

    pub(crate) fn emit_write(&self, domain: &'static str, path: &Path) {
        self.events.emit(domain, StorageOperation::Write, path);
    }
}
