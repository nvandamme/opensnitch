use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result};

use super::{SubscriptionRecord, SubscriptionService};
use crate::services::storage::StorageService;
use crate::utils::atomic_write::{
    finalize_atomic_replace, open_atomic_temp_file, sibling_temp_path_with_suffix,
};

impl SubscriptionService {
    async fn cleanup_temp_source_file(path: &std::path::Path) {
        let _ = StorageService::global()
            .remove_file_if_exists_and_notify("subscription", path)
            .await;
    }

    pub(super) async fn write_source_file(
        &self,
        filename: &str,
        format: &str,
        max_bytes: u64,
        body: &[u8],
    ) -> Result<()> {
        let sources_dir = self.root_dir.join("sources.list.d");
        StorageService::global()
            .create_dir_all_and_notify("subscription", &sources_dir)
            .await
            .with_context(|| {
                format!(
                    "creating subscription source dir: {}",
                    sources_dir.display()
                )
            })?;

        if (body.len() as u64) > max_bytes {
            anyhow::bail!(
                "response exceeds max-bytes limit ({} > {})",
                body.len(),
                max_bytes
            );
        }

        let source_path = sources_dir.join(filename);
        let temp_path = sibling_temp_path_with_suffix(&source_path, ".download");

        let mut file = open_atomic_temp_file(&temp_path, "source")?;

        const SAMPLE_LINES_MAX: usize = 200;
        let needs_validation = super::format::is_known_format(format);
        let mut sample_lines: Vec<String> = Vec::new();

        if needs_validation {
            let text = String::from_utf8_lossy(body);
            for line in text.lines().take(SAMPLE_LINES_MAX) {
                sample_lines.push(line.to_owned());
            }
        }

        if let Err(err) = file.write_all(body) {
            Self::cleanup_temp_source_file(&temp_path).await;
            return Err(err)
                .with_context(|| format!("writing temp source file: {}", temp_path.display()));
        }

        if needs_validation {
            if let Err(err) = super::format::validate_format_sample(format, &sample_lines) {
                Self::cleanup_temp_source_file(&temp_path).await;
                anyhow::bail!("{err}");
            }
        }

        finalize_atomic_replace(file, &temp_path, &source_path, "source")?;
        StorageService::global().emit_write("subscription", &source_path);

        Ok(())
    }

    pub(super) fn source_path_for(&self, record: &SubscriptionRecord) -> PathBuf {
        self.root_dir.join("sources.list.d").join(&record.filename)
    }
}
