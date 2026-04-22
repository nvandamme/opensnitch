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
        rule_record::{RuleDuration, RuleRecord},
        rule_storage::{RuleFile, RuleFileOperator},
    },
    services::storage::StorageService,
    utils::path_text::file_name_lossy,
    utils::transient_files::is_transient_artifact_name,
    workers::runtime::{control::WorkerControl, watch::control::WatchWorkerControl},
};

impl RuleService {
    pub(crate) async fn load_rules_from_path(
        path: &Path,
    ) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
        let mut loaded = Vec::new();
        let mut temporary_rules = Vec::new();
        let storage = StorageService::global();

        let entries = match storage.list_dir("rule", path).await {
            Ok(entries) => entries,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read rules directory {}", path.display()));
            }
        };

        for file_path in entries {
            if file_path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }

            let rule_file: RuleFile = storage
                .read_json_and_notify("rule", &file_path)
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
                if normalized.is_empty() || normalized.starts_with('#') {
                    return None;
                }
                Some(normalized.to_string())
            })
            .collect()
    }

    pub(crate) async fn load_network_aliases_map() -> HashMap<String, Vec<String>> {
        let Some(path) = Self::resolve_network_aliases_path().await else {
            return HashMap::new();
        };

        let Ok(Some(map)) = StorageService::global()
            .read_json_if_exists_and_notify::<HashMap<String, Vec<String>>>("rule", path.as_path())
            .await
        else {
            return HashMap::new();
        };

        map
    }

    pub(crate) async fn resolve_network_aliases_path() -> Option<PathBuf> {
        let storage = StorageService::global();
        if let Some(path) = std::env::var_os("OPENSNITCH_NETWORK_ALIASES_FILE").map(PathBuf::from)
            && storage.path_exists("rule", path.as_path()).await.ok()?
        {
            return Some(path);
        }

        let system_path = PathBuf::from("/etc/opensnitchd/network_aliases.json");
        if storage
            .path_exists("rule", system_path.as_path())
            .await
            .ok()?
        {
            return Some(system_path);
        }

        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("daemon/data/network_aliases.json");
        storage
            .path_exists("rule", dev_path.as_path())
            .await
            .ok()?
            .then_some(dev_path)
    }

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

    pub(crate) async fn read_rules_dir_file_state_async(
        path: &Path,
    ) -> Option<BTreeMap<String, Option<SystemTime>>> {
        let mut state = BTreeMap::new();
        let mut list_dirs = BTreeSet::new();
        let storage = StorageService::global();
        let entries = storage.list_dir_with_metadata("rule", path).await.ok()?;

        for entry in entries {
            let file_path = entry.path;
            if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let name = file_name_lossy(&file_path)?;
            state.insert(name, entry.modified);

            let Ok(rule_file) = storage.read_json::<RuleFile>("rule", &file_path).await else {
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

    fn scan<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let rules = self.rules.clone();
        let last_state = self.last_state.clone();
        Box::pin(async move {
            let snapshot = rules.snapshot();
            let path = snapshot.rules_path.as_path();
            StorageService::global().emit_scan("rule", path);
            let state = RuleService::read_rules_dir_file_state_async(path).await;
            let mut previous_guard = last_state.lock().await;

            let changed = match (&*previous_guard, &state) {
                (Some(prev), Some(cur)) => prev != cur,
                (None, Some(_)) => false,
                (Some(_), None) => true,
                (None, None) => false,
            };

            if changed {
                let previous_default = BTreeMap::new();
                let current_default = BTreeMap::new();
                let previous_files = previous_guard.as_ref().unwrap_or(&previous_default);
                let current_files = state.as_ref().unwrap_or(&current_default);
                for file_name in RuleService::diff_rule_files(previous_files, current_files) {
                    tracing::info!("Ruleset changed due to {}, reloading ...", file_name);
                }
                let previous_rules = rules.get_proto_snapshot();
                if let Err(err) = rules.reload().await {
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

            *previous_guard = state;
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
    }
    .build(shutdown)
}
