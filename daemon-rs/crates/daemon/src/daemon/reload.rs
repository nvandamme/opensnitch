use tracing::{error, info};

use super::Daemon;
use crate::{
    config::DefaultAction,
    utils::config_reload::{
        RuntimeApplyMessageContext, RuntimeApplyPolicy, RuntimeApplyStage,
        apply_runtime_config_services, apply_runtime_core, runtime_apply_stage_messages,
    },
    utils::systemd_notify::{NotifyState, notify},
};

impl Daemon {
    pub(super) async fn reload_runtime_after_sighup(&self) {
        notify(NotifyState::Reloading(Some(
            "SIGHUP received, reloading runtime config...",
        )));
        info!("SIGHUP received, reloading runtime config");

        let updated = match self.inner.config.reload().await {
            Ok(config) => config,
            Err(err) => {
                error!("failed to reload config from disk after SIGHUP: {err}");
                notify(NotifyState::Status("SIGHUP reload failed while reading config"));
                return;
            }
        };

        apply_runtime_core(&updated, &self.inner.stats);

        let apply_report = apply_runtime_config_services(
            &updated,
            &self.inner.rules,
            &self.inner.firewall,
            RuntimeApplyPolicy::StopAfterRulesError,
        )
        .await;

        for (stage, err) in apply_report.into_stage_errors() {
            let messages = runtime_apply_stage_messages(RuntimeApplyMessageContext::Sighup, stage);
            error!("{}: {err}", messages.log);
            if !matches!(stage, RuntimeApplyStage::Logging) {
                notify(NotifyState::Status(messages.external));
                return;
            }
        }

        if let Err(err) = self
            .reconfigure_proc_workers(Some(updated.proc_monitor_method))
            .await
        {
            error!("failed to reconfigure process monitor workers after SIGHUP: {err}");
            notify(NotifyState::Status(
                "SIGHUP reload failed while reconfiguring process monitor",
            ));
            return;
        }

        info!("SIGHUP reload completed");
        notify(NotifyState::Ready(Some("SIGHUP reload complete")));
    }

    pub(super) fn parse_default_action_from_client_config(
        raw_config_json: &str,
    ) -> Option<DefaultAction> {
        DefaultAction::from_raw_config_json(raw_config_json)
    }
}
