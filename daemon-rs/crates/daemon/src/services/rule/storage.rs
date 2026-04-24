use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
    time::SystemTime,
};

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{RuleService, rule_duration_temporary_spec};
use crate::{
    models::{
        rule_record::{RuleDuration, RuleOperator, RuleRecord},
        rule_storage::RuleFile,
    },
    platform::{
        adapters::loadable_state_file_store::FileLoadableStateStoreAdapter,
        ports::loadable_state_store_port::{AliasStorePort, RuleStorePort},
    },
    services::storage::StorageService,
    utils::path_text::file_name_lossy,
    utils::transient_files::is_transient_artifact_name,
    workers::runtime::{control::WorkerControl, watch::control::WatchWorkerControl},
};

#[cfg(test)]
use crate::models::rule_storage::RuleFileOperator;

pub(crate) struct RuleDirScanWithHint {
    pub(crate) state: BTreeMap<String, Option<SystemTime>>,
    pub(crate) rule_paths: Vec<PathBuf>,
}

impl RuleService {
    pub(crate) async fn load_rules_from_path(
        path: &Path,
    ) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
        let storage = StorageService::global();
        let entries = match storage.list_dir("rule", path).await {
            Ok(entries) => entries,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read rules directory {}", path.display()));
            }
        };

        Self::load_rules_from_paths(entries).await
    }

    pub(crate) async fn load_rules_from_paths(
        mut rule_paths: Vec<PathBuf>,
    ) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
        let mut loaded = Vec::new();
        let mut temporary_rules = Vec::new();
        let storage = StorageService::global();

        rule_paths.sort();

        for file_path in rule_paths {
            if !storage.path_matches_main_storage_format(&file_path) {
                continue;
            }

            let rule_file: RuleFile = FileLoadableStateStoreAdapter::load_rule_file(&file_path)
                .await
                .with_context(|| format!("failed to load rule file {}", file_path.display()))?;
            let record = RuleRecord::from(rule_file);
            if record.enabled
                && let Err(err) = Self::validate_operator(&record.operator)
            {
                warn!(
                    file = %file_path.display(),
                    rule = %record.name,
                    err = %err,
                    "skipping invalid enabled rule"
                );
                continue;
            }
            if record.enabled && rule_duration_temporary_spec(&record.duration).is_some() {
                temporary_rules.push((record.name.clone(), record.duration.clone()));
            }
            loaded.push(record);
        }

        loaded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

        Ok((loaded, temporary_rules))
    }

    /// Synchronous rule loading — batches all file I/O into the caller's
    /// thread, avoiding per-file `spawn_blocking` roundtrips.  Used by the
    /// inotify fast-path reload where latency matters.
    pub(crate) fn load_rules_from_path_sync(
        path: &Path,
    ) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
        let mut loaded = Vec::new();
        let mut temporary_rules = Vec::new();

        let entries = std::fs::read_dir(path)
            .with_context(|| format!("failed to read rules directory {}", path.display()))?;

        let storage = StorageService::global();
        let mut rule_paths: Vec<PathBuf> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if storage.path_matches_main_storage_format(&path) {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();
        rule_paths.sort();

        for file_path in rule_paths {
            let contents = std::fs::read_to_string(&file_path)
                .with_context(|| format!("failed to read rule file {}", file_path.display()))?;
            let mut rule_file: RuleFile =
                StorageService::parse_with_storage_format_for_path(&file_path, &contents)
                    .with_context(|| {
                        format!("failed to parse rule file {}", file_path.display())
                    })?;
            rule_file
                .normalize_legacy_operator_lists()
                .with_context(|| {
                    format!(
                        "failed to normalize legacy rule list payloads {}",
                        file_path.display()
                    )
                })?;
            let record = RuleRecord::from(rule_file);
            if record.enabled
                && let Err(err) = Self::validate_operator(&record.operator)
            {
                warn!(
                    file = %file_path.display(),
                    rule = %record.name,
                    err = %err,
                    "skipping invalid enabled rule"
                );
                continue;
            }
            if record.enabled && rule_duration_temporary_spec(&record.duration).is_some() {
                temporary_rules.push((record.name.clone(), record.duration.clone()));
            }
            loaded.push(record);
        }

        loaded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

        Ok((loaded, temporary_rules))
    }

    pub(crate) async fn load_list_entries_async_plain(path: &Path) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        let storage = StorageService::global();

        let dir_entries = match storage.list_dir_with_metadata("rule", path).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(err) => return Err(err.into()),
        };

        for entry in dir_entries {
            let file_path = entry.path;
            if !entry.is_file {
                continue;
            }

            let Some(name) = file_path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }

            let raw = storage
                .read_to_string_and_notify("rule", &file_path)
                .await?;
            let file_entries = Self::parse_list_lines(raw.lines());

            entries.extend(file_entries);
        }

        Ok(entries)
    }

    pub(crate) fn parse_list_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
        lines
            .filter_map(|line| {
                let normalized = line.strip_suffix('\r').unwrap_or(line);
                // '#' = hosts/plain-list comment; '!' = AdBlock/AdGuard comment.
                if normalized.is_empty()
                    || normalized.starts_with('#')
                    || normalized.starts_with('!')
                {
                    return None;
                }
                Some(normalized.to_string())
            })
            .collect()
    }

    pub(crate) async fn load_network_aliases_map(path: &Path) -> HashMap<String, Vec<String>> {
        let Ok(Some(map)) = FileLoadableStateStoreAdapter::load_alias_map(path).await else {
            return HashMap::new();
        };
        map
    }

    /// Called only from `read_rules_dir_file_state_async` (which is itself test-only).
    #[cfg(test)]
    pub(crate) fn collect_rule_list_dirs(
        operator: &RuleFileOperator,
        list_dirs: &mut BTreeSet<PathBuf>,
    ) {
        if Self::operator_is_lists(operator.r#type.as_str(), operator.operand.as_str()) {
            let path = PathBuf::from(operator.data.as_str());
            if !path.as_os_str().is_empty() {
                list_dirs.insert(path);
            }
        }

        for child in &operator.list {
            Self::collect_rule_list_dirs(child, list_dirs);
        }
    }

    /// Mirrors [`collect_rule_list_dirs`] but operates on the in-memory
    /// [`RuleOperator`] (field `type_name`) rather than the on-disk
    /// [`RuleFileOperator`] (field `r#type`), avoiding disk reads.
    fn collect_list_dirs_from_rule_operator(
        operator: &RuleOperator,
        list_dirs: &mut BTreeSet<PathBuf>,
    ) {
        if Self::operator_is_lists(operator.type_name.as_str(), operator.operand.as_str()) {
            let path = PathBuf::from(operator.data.as_str());
            if !path.as_os_str().is_empty() {
                list_dirs.insert(path);
            }
        }
        for child in &operator.list {
            Self::collect_list_dirs_from_rule_operator(child, list_dirs);
        }
    }

    /// Collect all list directory paths referenced by active rules in the snapshot.
    /// Used to prime the hint for [`read_rules_dir_scan_with_hint`] so the
    /// scan/detection pass can skip re-reading every JSON rule file.
    pub(crate) fn snapshot_list_dirs(rules: &[RuleRecord]) -> BTreeSet<PathBuf> {
        let mut list_dirs = BTreeSet::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            Self::collect_list_dirs_from_rule_operator(&rule.operator, &mut list_dirs);
        }
        list_dirs
    }

    /// Like [`read_rules_dir_file_state_async`] but takes pre-known list
    /// directories from the in-memory snapshot instead of re-reading every JSON
    /// rule file.  Use this on the watch-worker scan hot path; fall back to
    /// [`read_rules_dir_file_state_async`] when no snapshot is available.
    pub(crate) async fn read_rules_dir_scan_with_hint(
        path: &Path,
        known_list_dirs: &BTreeSet<PathBuf>,
    ) -> Option<RuleDirScanWithHint> {
        let mut state = BTreeMap::new();
        let mut rule_paths = Vec::new();
        let storage = StorageService::global();
        let entries = storage.list_dir_with_metadata("rule", path).await.ok()?;

        for entry in entries {
            let file_path = entry.path;
            if !storage.path_matches_main_storage_format(&file_path) {
                continue;
            }
            let name = file_name_lossy(&file_path)?;
            state.insert(name, entry.modified);
            rule_paths.push(file_path);
            // No JSON read — list dirs come from the caller's snapshot hint.
        }

        rule_paths.sort();

        for list_dir in known_list_dirs {
            let Ok(list_entries) = storage.list_dir_with_metadata("rule", list_dir).await else {
                continue;
            };
            for list_entry in list_entries {
                let list_path = list_entry.path;
                let Some(file_name) = list_path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if is_transient_artifact_name(file_name) {
                    continue;
                }
                if !list_entry.is_file {
                    continue;
                }
                let key = format!("list:{}:{}", list_dir.display(), file_name);
                state.insert(key, list_entry.modified);
            }
        }

        Some(RuleDirScanWithHint { state, rule_paths })
    }

    /// Fallback when no in-memory snapshot is available.
    /// Production code uses [`read_rules_dir_scan_with_hint`] on the hot path;
    /// this variant is used by tests.
    #[cfg(test)]
    pub(crate) async fn read_rules_dir_file_state_async(
        path: &Path,
    ) -> Option<BTreeMap<String, Option<SystemTime>>> {
        let mut state = BTreeMap::new();
        let mut list_dirs = BTreeSet::new();
        let storage = StorageService::global();
        let entries = storage.list_dir_with_metadata("rule", path).await.ok()?;

        for entry in entries {
            let file_path = entry.path;
            if !storage.path_matches_main_storage_format(&file_path) {
                continue;
            }
            let name = file_name_lossy(&file_path)?;
            state.insert(name, entry.modified);

            let Ok(rule_file) = storage
                .read_and_parse_with_storage_format::<RuleFile>("rule", &file_path)
                .await
            else {
                continue;
            };

            if !rule_file.enabled {
                continue;
            }

            Self::collect_rule_list_dirs(&rule_file.operator, &mut list_dirs);
        }

        for list_dir in list_dirs {
            let Ok(list_entries) = storage.list_dir_with_metadata("rule", &list_dir).await else {
                continue;
            };

            for list_entry in list_entries {
                let list_path = list_entry.path;
                let Some(file_name) = list_path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if is_transient_artifact_name(file_name) {
                    continue;
                }

                if !list_entry.is_file {
                    continue;
                }

                let key = format!("list:{}:{}", list_dir.display(), file_name);
                state.insert(key, list_entry.modified);
            }
        }

        Some(state)
    }
}

struct RuleWatchControl {
    rules: RuleService,
    targets: Vec<PathBuf>,
    last_state: Arc<tokio::sync::Mutex<Option<BTreeMap<String, Option<SystemTime>>>>>,
    /// When `true`, this scan was triggered by an inotify event — the kernel
    /// already told us something changed so we skip the redundant readdir+stat
    /// state-comparison pass and go straight to reload.
    inotify_hint: bool,
}

impl WatchWorkerControl for RuleWatchControl {
    fn worker_name(&self) -> &'static str {
        "rules-watch"
    }

    fn poll_interval(&self) -> Duration {
        Self::poll_every_secs(2)
    }

    fn targets(&self) -> Vec<PathBuf> {
        self.targets.clone()
    }

    fn set_inotify_hint(&mut self, inotify: bool) {
        self.inotify_hint = inotify;
    }

    fn scan<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let rules = self.rules.clone();
        let last_state = self.last_state.clone();
        let forced = self.inotify_hint;
        Box::pin(async move {
            let snapshot = rules.snapshot();
            let path = snapshot.rules_path.as_path();
            StorageService::global().emit_scan("rule", path);

            if forced {
                // inotify told us something changed — skip the readdir+stat
                // state-comparison and reload directly (single directory pass).
                // Uses reload_inline to avoid the spawn_blocking scheduling
                // overhead (~3-5 ms) — the rules directory holds a handful of
                // tiny JSON files whose sync I/O completes in microseconds.
                let previous_rules = rules.get_wire_snapshot();
                if let Err(err) = rules.reload_inline().await {
                    tracing::error!(path = %path.display(), "failed to reload rules after inotify event: {err}");
                } else {
                    tracing::info!(path = %path.display(), "rules reloaded after inotify event");
                }

                // Log removed rules by comparing previous vs new snapshots.
                let new_snapshot = rules.snapshot();
                let new_names: std::collections::HashSet<&str> =
                    new_snapshot.rules.iter().map(|r| r.name.as_str()).collect();
                for rule in previous_rules.iter() {
                    if !new_names.contains(rule.name.as_str()) {
                        tracing::info!("{}", RuleService::format_deleted_rule(rule));
                        let extension = StorageService::global().main_storage_extension();
                        tracing::info!("Rule deleted {}.{}", rule.name, extension);
                    }
                }

                // Invalidate cached state so the next poll tick re-derives it
                // without triggering another reload.  This keeps the readdir+stat
                // off the inotify critical path entirely.
                *last_state.lock().await = None;
                return;
            }

            // Poll-triggered scan: read directory state and compare with
            // previous to avoid unnecessary reloads.
            let known_list_dirs = RuleService::snapshot_list_dirs(&snapshot.rules);
            let scanned = RuleService::read_rules_dir_scan_with_hint(path, &known_list_dirs).await;
            let (state, scanned_rule_paths) = match scanned {
                Some(scan) => (Some(scan.state), Some(scan.rule_paths)),
                None => (None, None),
            };

            let previous = last_state.lock().await.clone();

            let changed = match (&previous, &state) {
                (Some(prev), Some(cur)) => prev != cur,
                (None, Some(_)) => false,
                (Some(_), None) => true,
                (None, None) => false,
            };

            if changed {
                let previous_default = BTreeMap::new();
                let current_default = BTreeMap::new();
                let previous_files = previous.as_ref().unwrap_or(&previous_default);
                let current_files = state.as_ref().unwrap_or(&current_default);
                for file_name in RuleService::diff_rule_files(previous_files, current_files) {
                    tracing::info!("Ruleset changed due to {}, reloading ...", file_name);
                }
                let previous_rules = rules.get_wire_snapshot();
                let reload_result = if let Some(rule_paths) = scanned_rule_paths {
                    rules.reload_from_rule_paths(rule_paths).await
                } else {
                    rules.reload().await
                };

                if let Err(err) = reload_result {
                    tracing::error!(path = %path.display(), "failed to reload rules after directory change: {err}");
                } else {
                    for file_name in RuleService::removed_rule_files(previous_files, current_files)
                    {
                        if let Some(stem) = std::path::Path::new(&file_name)
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            && let Some(rule) = previous_rules.iter().find(|rule| rule.name == stem)
                        {
                            tracing::info!("{}", RuleService::format_deleted_rule(rule));
                        }
                        tracing::info!("Rule deleted {}", file_name);
                    }
                    tracing::info!(path = %path.display(), "rules reloaded after directory change");
                }
            }

            *last_state.lock().await = state;
        })
    }
}

pub(super) fn start_rule_watch_task(
    rules: RuleService,
    shutdown: CancellationToken,
) -> Box<dyn WorkerControl> {
    let snapshot = rules.snapshot();
    let targets = RuleWatchControl::path_targets(snapshot.rules_path.as_path());

    RuleWatchControl {
        rules,
        targets,
        last_state: Arc::new(tokio::sync::Mutex::new(None)),
        inotify_hint: false,
    }
    .build(shutdown)
}
