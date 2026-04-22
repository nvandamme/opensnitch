use std::io::ErrorKind;

use anyhow::Result;
use tracing::{debug, warn};

use crate::models::rule_record::{RuleDuration, RuleRecord};
use crate::models::rule_storage::RuleFile;
use crate::services::storage::StorageService;

use super::{RuleService, rule_duration_persists_to_disk, rule_duration_temporary_spec};

impl RuleService {
    fn rule_storage_path(rules_path: &std::path::Path, rule_name: &str) -> std::path::PathBuf {
        let extension = StorageService::global().main_storage_extension();
        rules_path.join(format!("{rule_name}.{extension}"))
    }

    async fn remove_rule_file_if_missing_ok(file_path: &std::path::Path) -> Result<()> {
        if let Err(err) = StorageService::global()
            .remove_file_if_exists_and_notify("rule", file_path)
            .await
        {
            if err.kind() != ErrorKind::NotFound {
                return Err(err.into());
            }
        }
        Ok(())
    }

    pub async fn delete_by_name(&self, rule_name: &str) -> Result<()> {
        let _update_guard = self.update_lock.lock().await;
        let current = self.snapshot();
        let mut next_rules = current.rules.iter().cloned().collect::<Vec<_>>();
        let rules_path = current.rules_path.as_path();
        next_rules.retain(|rule| rule.name != rule_name);

        let file_path = Self::rule_storage_path(rules_path, rule_name);
        Self::remove_rule_file_if_missing_ok(&file_path).await?;

        self.build_and_publish_snapshot(rules_path, next_rules)
            .await?;

        Ok(())
    }

    pub(super) async fn upsert_record(&self, record: RuleRecord) -> Result<()> {
        let _update_guard = self.update_lock.lock().await;
        let mut old_persisted = false;
        let current = self.snapshot();
        let mut next_rules = current.rules.iter().cloned().collect::<Vec<_>>();
        let rules_path = current.rules_path.as_path();
        if let Some(existing) = next_rules
            .iter_mut()
            .find(|current| current.name == record.name)
        {
            old_persisted = rule_duration_persists_to_disk(&existing.duration);
            *existing = record.clone();
        } else {
            next_rules.push(record.clone());
            next_rules.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        }

        let new_persisted = rule_duration_persists_to_disk(&record.duration);
        let file_path = Self::rule_storage_path(rules_path, record.name.as_str());
        if old_persisted && !new_persisted {
            Self::remove_rule_file_if_missing_ok(&file_path).await?;
        }

        if new_persisted {
            StorageService::global()
                .convert_and_write_with_storage_format_to_path_and_notify(
                    "rule",
                    &file_path,
                    &RuleFile::from(&record),
                    true,
                )
                .await?;
        }

        self.build_and_publish_snapshot(rules_path, next_rules)
            .await?;

        if record.enabled && rule_duration_temporary_spec(&record.duration).is_some() {
            self.schedule_temporary_rule(record.name.clone(), record.duration.clone());
        }

        Ok(())
    }

    pub(super) fn schedule_temporary_rule(&self, rule_name: String, duration: RuleDuration) {
        let Some(duration_spec) = rule_duration_temporary_spec(&duration).map(ToOwned::to_owned)
        else {
            return;
        };
        let Some(timeout) = Self::parse_duration_spec(&duration_spec) else {
            warn!(rule = %rule_name, duration = %duration_spec, "invalid temporary rule duration; skipping expiry scheduling");
            return;
        };

        let service = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            let _update_guard = service.update_lock.lock().await;
            let current = service.snapshot();
            let mut next_rules = current.rules.iter().cloned().collect::<Vec<_>>();
            let rules_path = current.rules_path.as_path();
            let Some(idx) = next_rules.iter().position(|item| item.name == rule_name) else {
                return;
            };

            let current_rule = &next_rules[idx];
            if !current_rule.enabled {
                return;
            }
            if rule_duration_temporary_spec(&current_rule.duration) != Some(duration_spec.as_str())
            {
                return;
            }

            debug!(rule = %rule_name, duration = %duration_spec, "temporary rule expired");
            next_rules.remove(idx);

            if let Err(err) = service
                .build_and_publish_snapshot(rules_path, next_rules)
                .await
            {
                warn!(rule = %rule_name, err = %err, "failed to refresh rule match caches after expiry");
            }
        });
    }
}
