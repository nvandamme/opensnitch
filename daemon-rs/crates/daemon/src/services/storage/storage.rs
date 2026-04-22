use std::{
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use storage_format_core::StorageFormatCodec;
#[cfg(feature = "storage-format-json")]
use storage_format_json::JsonStorageFormat;
#[cfg(feature = "storage-format-toml")]
use storage_format_toml::TomlStorageFormat;
#[cfg(feature = "storage-format-yaml")]
use storage_format_yaml::YamlStorageFormat;

use super::event_bus::StorageEventBus;
use super::runtime_lifecycle::{
    global_storage_service, reload_global_storage_service, subscribe_global_storage_reload,
};

pub(crate) use super::event_bus::StorageEventSubscription;
pub(crate) use crate::models::storage_dir_entry::StorageDirEntry;
pub(crate) use crate::models::storage_event::{StorageEvent, StorageOperation};

use crate::utils::atomic_write::{write_bytes_atomic_async, write_bytes_atomic_sync};

fn option_if_not_found<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

use crate::{
    models::audit::{AuditEvent, AuditEventKind, StorageAction},
    services::audit::AuditService,
};

#[cfg(not(any(
    feature = "storage-format-json",
    feature = "storage-format-yaml",
    feature = "storage-format-toml"
)))]
compile_error!(
    "opensnitchd-rs requires at least one storage codec feature: storage-format-json, storage-format-yaml, or storage-format-toml"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageFormat {
    Json,
    Yaml,
    Toml,
}

impl StorageFormat {
    pub(crate) fn compiled_default() -> Self {
        #[cfg(feature = "storage-format-json")]
        {
            Self::Json
        }

        #[cfg(all(not(feature = "storage-format-json"), feature = "storage-format-yaml"))]
        {
            Self::Yaml
        }

        #[cfg(all(
            not(feature = "storage-format-json"),
            not(feature = "storage-format-yaml"),
            feature = "storage-format-toml"
        ))]
        {
            Self::Toml
        }
    }

    pub(crate) fn from_cli_flag(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            #[cfg(feature = "storage-format-json")]
            "json" => Some(Self::Json),
            #[cfg(feature = "storage-format-yaml")]
            "yaml" | "yml" => Some(Self::Yaml),
            #[cfg(feature = "storage-format-toml")]
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .ok_or_else(|| anyhow::anyhow!("storage file has no extension: {}", path.display()))?;

        match ext.as_str() {
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            "toml" => Ok(Self::Toml),
            _ => Err(anyhow::anyhow!(
                "unsupported storage format extension '{ext}' for {}",
                path.display()
            )),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Yaml => "YAML",
            Self::Toml => "TOML",
        }
    }

    pub(crate) fn canonical_extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Toml => "toml",
        }
    }

    fn matches_path(&self, path: &Path) -> bool {
        let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
            return false;
        };
        let ext = ext.to_ascii_lowercase();
        match self {
            Self::Json => ext == "json",
            Self::Yaml => ext == "yaml" || ext == "yml",
            Self::Toml => ext == "toml",
        }
    }

    fn parse<T>(&self, raw: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        match self {
            Self::Json => {
                #[cfg(feature = "storage-format-json")]
                {
                    return Ok(JsonStorageFormat.parse_from_storage(raw)?);
                }
                #[cfg(not(feature = "storage-format-json"))]
                {
                    return Err(anyhow::anyhow!("JSON storage format feature is disabled"));
                }
            }
            Self::Yaml => {
                #[cfg(feature = "storage-format-yaml")]
                {
                    return Ok(YamlStorageFormat.parse_from_storage(raw)?);
                }
                #[cfg(not(feature = "storage-format-yaml"))]
                {
                    return Err(anyhow::anyhow!("YAML storage format feature is disabled"));
                }
            }
            Self::Toml => {
                #[cfg(feature = "storage-format-toml")]
                {
                    return Ok(TomlStorageFormat.parse_from_storage(raw)?);
                }
                #[cfg(not(feature = "storage-format-toml"))]
                {
                    return Err(anyhow::anyhow!("TOML storage format feature is disabled"));
                }
            }
        }
    }

    fn convert<T>(&self, value: &T, pretty: bool) -> Result<String>
    where
        T: Serialize,
    {
        match self {
            Self::Json => {
                #[cfg(feature = "storage-format-json")]
                {
                    if pretty {
                        return Ok(JsonStorageFormat.convert_to_storage_pretty(value)?);
                    }
                    return Ok(JsonStorageFormat.convert_to_storage(value)?);
                }
                #[cfg(not(feature = "storage-format-json"))]
                {
                    return Err(anyhow::anyhow!("JSON storage format feature is disabled"));
                }
            }
            Self::Yaml => {
                #[cfg(feature = "storage-format-yaml")]
                {
                    if pretty {
                        return Ok(YamlStorageFormat.convert_to_storage_pretty(value)?);
                    }
                    return Ok(YamlStorageFormat.convert_to_storage(value)?);
                }
                #[cfg(not(feature = "storage-format-yaml"))]
                {
                    return Err(anyhow::anyhow!("YAML storage format feature is disabled"));
                }
            }
            Self::Toml => {
                #[cfg(feature = "storage-format-toml")]
                {
                    if pretty {
                        return Ok(TomlStorageFormat.convert_to_storage_pretty(value)?);
                    }
                    return Ok(TomlStorageFormat.convert_to_storage(value)?);
                }
                #[cfg(not(feature = "storage-format-toml"))]
                {
                    return Err(anyhow::anyhow!("TOML storage format feature is disabled"));
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct StorageService {
    events: StorageEventBus,
    audit: Option<AuditService>,
    verbose_hot_path_audit: bool,
    main_storage_format: Option<StorageFormat>,
}

impl StorageService {
    pub(crate) fn new() -> Self {
        Self {
            events: StorageEventBus::new(),
            audit: None,
            verbose_hot_path_audit: false,
            main_storage_format: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_audit(mut self, audit: AuditService) -> Self {
        self.audit = Some(audit);
        self
    }

    pub(crate) fn with_verbose_hot_path_audit(mut self, enabled: bool) -> Self {
        self.verbose_hot_path_audit = enabled;
        self
    }

    pub(crate) fn with_main_storage_format(
        mut self,
        storage_format: Option<StorageFormat>,
    ) -> Self {
        self.main_storage_format = storage_format;
        self
    }

    pub(super) fn with_optional_audit(mut self, audit: Option<AuditService>) -> Self {
        self.audit = audit;
        self
    }

    pub(super) fn audit_handle(&self) -> Option<AuditService> {
        self.audit.clone()
    }

    pub(super) fn verbose_hot_path_audit_enabled(&self) -> bool {
        self.verbose_hot_path_audit
    }

    pub(super) fn main_storage_format(&self) -> Option<StorageFormat> {
        self.main_storage_format
    }

    pub(crate) fn global() -> Self {
        global_storage_service()
    }

    pub(crate) fn install_global_audit(audit: AuditService, verbose_hot_path: bool) -> Self {
        let mut current = global_storage_service();
        current.audit = Some(audit);
        current.verbose_hot_path_audit = verbose_hot_path;
        super::runtime_lifecycle::replace_global_storage_service(current)
    }

    pub(crate) fn install_global_main_storage_format(
        storage_format: Option<StorageFormat>,
    ) -> Self {
        let mut current = global_storage_service();
        current.main_storage_format = storage_format;
        super::runtime_lifecycle::replace_global_storage_service(current)
    }
    pub(crate) fn reload_global() -> Self {
        reload_global_storage_service()
    }
    pub(crate) fn subscribe_global_reload() -> tokio::sync::watch::Receiver<u64> {
        subscribe_global_storage_reload()
    }
    pub(crate) fn subscribe_events(&self) -> StorageEventSubscription {
        self.events.subscribe()
    }
    #[allow(dead_code)]
    pub(crate) fn subscribe_events_for_path(&self, path: &Path) -> StorageEventSubscription {
        self.events.subscribe_for_path(path)
    }
    #[allow(dead_code)]
    pub(crate) fn subscribe_events_for_prefix(&self, path: &Path) -> StorageEventSubscription {
        self.events.subscribe_for_prefix(path)
    }

    pub(crate) fn dropped_ingress_events_count(&self) -> u64 {
        self.events.dropped_ingress_events() as u64
    }

    pub(crate) fn main_storage_extension(&self) -> &'static str {
        self.main_storage_format
            .unwrap_or(StorageFormat::compiled_default())
            .canonical_extension()
    }

    pub(crate) fn path_matches_main_storage_format(&self, path: &Path) -> bool {
        self.main_storage_format
            .unwrap_or(StorageFormat::compiled_default())
            .matches_path(path)
    }

    fn resolve_storage_format(&self, path: &Path) -> StorageFormat {
        if let Some(storage_format) = self.main_storage_format {
            return storage_format;
        }

        StorageFormat::from_path(path).unwrap_or(StorageFormat::compiled_default())
    }

    #[allow(dead_code)]
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
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => {
                self.emit_storage_read(domain, path);
                Ok(contents)
            }
            Err(err) => {
                self.emit_storage_read_failed(path, &err);
                Err(err)
            }
        }
    }
    #[allow(dead_code)]
    pub(crate) async fn read_to_string_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<String>> {
        option_if_not_found(tokio::fs::read_to_string(path).await)
    }

    pub(crate) async fn read_to_string_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<String>> {
        let maybe_contents = option_if_not_found(tokio::fs::read_to_string(path).await)?;
        if maybe_contents.is_some() {
            self.emit_storage_read(domain, path);
        }
        Ok(maybe_contents)
    }

    #[allow(dead_code)]
    pub(crate) fn read_to_string_sync(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    #[allow(dead_code)]
    pub(crate) fn read_to_string_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<String> {
        let contents = std::fs::read_to_string(path)?;
        self.emit_storage_read(domain, path);
        Ok(contents)
    }
    #[allow(dead_code)]
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
        self.emit_storage_read(domain, path);
        Ok(contents)
    }

    #[allow(dead_code)]
    pub(crate) async fn read_and_parse_with_storage_format<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let storage_format = self.resolve_storage_format(path);
        let raw = self
            .read_to_string(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?;
        storage_format
            .parse(&raw)
            .with_context(|| format!("parsing {} file {}", storage_format.label(), path.display()))
    }

    pub(crate) async fn read_and_parse_with_storage_format_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let storage_format = self.resolve_storage_format(path);
        let raw = self
            .read_to_string_and_notify(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?;
        storage_format
            .parse(&raw)
            .with_context(|| format!("parsing {} file {}", storage_format.label(), path.display()))
    }
    #[allow(dead_code)]
    pub(crate) async fn read_and_parse_with_storage_format_if_exists<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let storage_format = self.resolve_storage_format(path);
        let Some(raw) = self
            .read_to_string_if_exists(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?
        else {
            return Ok(None);
        };

        let parsed = storage_format.parse(&raw).with_context(|| {
            format!("parsing {} file {}", storage_format.label(), path.display())
        })?;
        Ok(Some(parsed))
    }

    pub(crate) async fn read_and_parse_with_storage_format_if_exists_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let storage_format = self.resolve_storage_format(path);
        let Some(raw) = self
            .read_to_string_if_exists_and_notify(domain, path)
            .await
            .with_context(|| format!("reading file {}", path.display()))?
        else {
            return Ok(None);
        };

        let parsed = storage_format.parse(&raw).with_context(|| {
            format!("parsing {} file {}", storage_format.label(), path.display())
        })?;
        Ok(Some(parsed))
    }
    #[allow(dead_code)]
    pub(crate) fn read_and_parse_with_storage_format_sync<T>(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let storage_format = self.resolve_storage_format(path);
        let raw = self
            .read_to_string_sync(domain, path)
            .with_context(|| format!("reading file {}", path.display()))?;
        storage_format
            .parse(&raw)
            .with_context(|| format!("parsing {} file {}", storage_format.label(), path.display()))
    }

    pub(crate) fn parse_with_storage_format_for_path<T>(path: &Path, raw: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let storage_format = global_storage_service().resolve_storage_format(path);
        storage_format
            .parse(raw)
            .with_context(|| format!("parsing {} file {}", storage_format.label(), path.display()))
    }
    #[allow(dead_code)]
    pub(crate) async fn remove_file_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        option_if_not_found(tokio::fs::remove_file(path).await).map(|m| m.is_some())
    }

    pub(crate) async fn remove_file_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let deleted = option_if_not_found(tokio::fs::remove_file(path).await)?.is_some();
        if deleted {
            self.events.emit_delete(domain, path);
        }
        Ok(deleted)
    }
    #[allow(dead_code)]
    pub(crate) async fn remove_path_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let Some(metadata) = option_if_not_found(tokio::fs::metadata(path).await)? else {
            return Ok(false);
        };

        if metadata.is_dir() {
            tokio::fs::remove_dir_all(path).await?;
        } else {
            tokio::fs::remove_file(path).await?;
        }
        Ok(true)
    }

    #[allow(dead_code)]
    pub(crate) async fn remove_path_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let Some(metadata) = option_if_not_found(tokio::fs::metadata(path).await)? else {
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
    #[allow(dead_code)]
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
        self.emit_write(domain, path);
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) fn create_dir_all_sync(&self, _domain: &'static str, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    pub(crate) fn create_dir_all_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        self.emit_write(domain, path);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn path_exists(&self, _domain: &'static str, path: &Path) -> io::Result<bool> {
        option_if_not_found(tokio::fs::metadata(path).await).map(|m| m.is_some())
    }
    #[allow(dead_code)]
    pub(crate) async fn path_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let exists = option_if_not_found(tokio::fs::metadata(path).await)?.is_some();
        if exists {
            self.emit_storage_read(domain, path);
        }
        Ok(exists)
    }

    #[allow(dead_code)]
    pub(crate) fn path_exists_sync(&self, _domain: &'static str, path: &Path) -> io::Result<bool> {
        option_if_not_found(std::fs::metadata(path)).map(|m| m.is_some())
    }
    #[allow(dead_code)]
    pub(crate) fn path_exists_sync_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<bool> {
        let exists = option_if_not_found(std::fs::metadata(path))?.is_some();
        if exists {
            self.emit_storage_read(domain, path);
        }
        Ok(exists)
    }

    pub(crate) async fn modified_time_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<SystemTime>> {
        let maybe_metadata = option_if_not_found(tokio::fs::metadata(path).await)?;
        Ok(maybe_metadata.and_then(|metadata| metadata.modified().ok()))
    }
    #[allow(dead_code)]
    pub(crate) async fn modified_time_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<SystemTime>> {
        let maybe_metadata = option_if_not_found(tokio::fs::metadata(path).await)?;
        if let Some(metadata) = maybe_metadata {
            self.emit_storage_read(domain, path);
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub(crate) async fn list_dir_with_metadata_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Vec<StorageDirEntry>> {
        let items = self.list_dir_with_metadata(domain, path).await?;
        self.events.emit(domain, StorageOperation::Scan, path);
        Ok(items)
    }

    #[allow(dead_code)]
    pub(crate) async fn read_link_if_exists(
        &self,
        _domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<PathBuf>> {
        option_if_not_found(tokio::fs::read_link(path).await)
    }
    #[allow(dead_code)]
    pub(crate) async fn read_link_if_exists_and_notify(
        &self,
        domain: &'static str,
        path: &Path,
    ) -> io::Result<Option<PathBuf>> {
        let maybe_target = option_if_not_found(tokio::fs::read_link(path).await)?;
        if maybe_target.is_some() {
            self.emit_storage_read(domain, path);
        }
        Ok(maybe_target)
    }
    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
        self.emit_write(domain, emitted_path.as_path());
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) async fn write_bytes_atomic(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        if let Err(err) = write_bytes_atomic_async(temp_path, path, bytes, domain).await {
            self.emit_storage_write_failed(path, &err);
            return Err(err);
        }
        Ok(())
    }

    pub(crate) async fn write_bytes_atomic_and_notify(
        &self,
        domain: &'static str,
        temp_path: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        if let Err(err) = write_bytes_atomic_async(temp_path, path, bytes, domain).await {
            self.emit_storage_write_failed(path, &err);
            return Err(err);
        }
        self.emit_write(domain, path);
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

    pub(crate) async fn convert_and_write_with_storage_format_to_path_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
        value: &T,
        pretty: bool,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let storage_format = self.resolve_storage_format(path);
        if let Some(parent) = path.parent() {
            self.create_dir_all_and_notify(domain, parent).await?;
        }

        let payload = storage_format.convert(value, pretty).with_context(|| {
            format!(
                "converting {} payload for {}",
                storage_format.label(),
                path.display()
            )
        })?;

        let temp_path = crate::utils::atomic_write::sibling_temp_path_with_suffix(path, ".tmp");
        self.write_bytes_atomic_and_notify(domain, &temp_path, path, payload.as_bytes())
            .await
    }
    #[allow(dead_code)]
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
        self.emit_write(domain, path);
        Ok(())
    }

    pub(crate) fn convert_and_write_with_storage_format_to_path_sync_and_notify<T>(
        &self,
        domain: &'static str,
        path: &Path,
        value: &T,
        pretty: bool,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let storage_format = self.resolve_storage_format(path);
        if let Some(parent) = path.parent() {
            self.create_dir_all_sync_and_notify(domain, parent)?;
        }

        let payload = storage_format.convert(value, pretty).with_context(|| {
            format!(
                "converting {} payload for {}",
                storage_format.label(),
                path.display()
            )
        })?;

        let temp_path = crate::utils::atomic_write::sibling_temp_path_with_suffix(path, ".tmp");
        self.write_bytes_atomic_sync_and_notify(domain, &temp_path, path, payload.as_bytes())
    }

    pub(crate) fn emit_scan(&self, domain: &'static str, path: &Path) {
        self.events.emit(domain, StorageOperation::Scan, path);
    }

    pub(crate) fn emit_write(&self, domain: &'static str, path: &Path) {
        self.events.emit_write(domain, path);
        self.emit_storage_write(domain, path);
    }

    fn emit_storage_read(&self, domain: &'static str, path: &Path) {
        self.events.emit_read(domain, path);
        if self.verbose_hot_path_audit {
            self.emit_storage_read_tracked(domain, path);
        }
    }

    fn emit_storage_read_tracked(&self, _domain: &'static str, path: &Path) {
        let Some(audit) = &self.audit else {
            return;
        };
        audit.emit(AuditEvent::hot(AuditEventKind::StorageAction(
            StorageAction::FileRead {
                path: path.display().to_string().into_boxed_str(),
            },
        )));
    }

    fn emit_storage_write(&self, _domain: &'static str, path: &Path) {
        if !self.verbose_hot_path_audit {
            return;
        }
        let Some(audit) = &self.audit else {
            return;
        };
        audit.emit(AuditEvent::hot(AuditEventKind::StorageAction(
            StorageAction::FileWritten {
                path: path.display().to_string().into_boxed_str(),
            },
        )));
    }

    fn emit_storage_read_failed(&self, path: &Path, err: &io::Error) {
        let Some(audit) = &self.audit else {
            return;
        };
        audit.emit(AuditEvent::cold(AuditEventKind::StorageAction(
            StorageAction::FileReadFailed {
                path: path.display().to_string().into_boxed_str(),
                reason: Self::storage_io_reason(err),
            },
        )));
    }

    fn emit_storage_write_failed(&self, path: &Path, err: &anyhow::Error) {
        let Some(audit) = &self.audit else {
            return;
        };
        let reason = err
            .downcast_ref::<io::Error>()
            .map(Self::storage_io_reason)
            .unwrap_or("io-error");
        audit.emit(AuditEvent::cold(AuditEventKind::StorageAction(
            StorageAction::FileWriteFailed {
                path: path.display().to_string().into_boxed_str(),
                reason,
            },
        )));
    }

    fn storage_io_reason(err: &io::Error) -> &'static str {
        match err.kind() {
            io::ErrorKind::NotFound => "not-found",
            io::ErrorKind::PermissionDenied => "permission-denied",
            io::ErrorKind::AlreadyExists => "already-exists",
            _ => "io-error",
        }
    }
}
