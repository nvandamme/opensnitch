use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result};
use tracing::warn;

use super::SubscriptionRecord;
use super::SubscriptionService;
use crate::services::storage::StorageService;
use crate::utils::name_parsing::sanitize_ascii_name;
use crate::utils::sort_key::sort_by_string_key;

impl SubscriptionService {
    async fn prune_stale_rule_groups(
        &self,
        rules_dir: &Path,
        desired_groups: &HashMap<String, Vec<(String, std::path::PathBuf)>>,
    ) {
        if let Ok(entries) = StorageService::global()
            .list_dir("subscription", rules_dir)
            .await
        {
            for stale_path in entries {
                let Some(name) = stale_path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if !desired_groups.contains_key(name) {
                    let _ = StorageService::global()
                        .remove_path_if_exists_and_notify("subscription", stale_path.as_path())
                        .await;
                }
            }
        }
    }

    async fn reconcile_rule_symlink(&self, link_path: &Path, target: &Path) -> Result<()> {
        if let Some(current) = StorageService::global()
            .read_link_if_exists("subscription", link_path)
            .await
            .unwrap_or(None)
        {
            if current == target {
                return Ok(());
            }

            let _ = StorageService::global()
                .remove_file_if_exists_and_notify("subscription", link_path)
                .await;
        }

        StorageService::global()
            .create_symlink_and_notify("subscription", target, link_path)
            .await
            .context(format!(
                "creating subscription symlink {} -> {}",
                link_path.display(),
                target.display()
            ))
    }

    pub(super) async fn sync_layout(&self) -> Result<()> {
        let sources_dir = self.root_dir.join("sources.list.d");
        let rules_dir = self.root_dir.join("rules.list.d");
        StorageService::global()
            .create_dir_all_and_notify("subscription", &sources_dir)
            .await?;
        StorageService::global()
            .create_dir_all_and_notify("subscription", &rules_dir)
            .await?;

        let items = self.storage.list_records();
        self.sync_rule_links(&items, &rules_dir).await?;
        Ok(())
    }

    pub(super) async fn sync_rule_links(
        &self,
        items: &[SubscriptionRecord],
        rules_dir: &Path,
    ) -> Result<()> {
        let sources_dir = self.root_dir.join("sources.list.d");
        let mut desired_groups: HashMap<String, Vec<(String, std::path::PathBuf)>> = HashMap::new();

        let mut enabled: Vec<&SubscriptionRecord> = items.iter().filter(|s| s.enabled).collect();
        sort_by_string_key(&mut enabled, |sub| sub.id.as_str());

        for (idx, sub) in enabled.iter().enumerate() {
            let source_path = sources_dir.join(&sub.filename);
            if !StorageService::global()
                .path_exists("subscription", &source_path)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let link_name = format!(
                "{:02}-{}.txt",
                idx,
                sanitize_ascii_name(sub.filename.trim_end_matches(".txt"))
            );
            let groups: Vec<String> = {
                let mut g = vec![sanitize_ascii_name(&sub.filename), "all".to_string()];
                g.extend(sub.groups.iter().map(|s| sanitize_ascii_name(s)));
                g.dedup();
                g
            };
            for group in &groups {
                desired_groups
                    .entry(group.clone())
                    .or_default()
                    .push((link_name.clone(), source_path.clone()));
            }
        }

        self.prune_stale_rule_groups(rules_dir, &desired_groups)
            .await;

        for (group, links) in &desired_groups {
            let group_dir = rules_dir.join(group);
            StorageService::global()
                .create_dir_all_and_notify("subscription", &group_dir)
                .await?;
            for (link_name, target) in links {
                let link_path = group_dir.join(link_name);
                if let Err(err) = self
                    .reconcile_rule_symlink(link_path.as_path(), target.as_path())
                    .await
                {
                    warn!(
                        link = %link_path.display(),
                        target = %target.display(),
                        "failed to create subscription rule symlink: {err}"
                    );
                }
            }
        }
        Ok(())
    }
}
