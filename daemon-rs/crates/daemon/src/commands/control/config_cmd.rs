use super::CommandControlService;
use super::control::{CONTROL_COMMAND_NOTIFICATION_LABEL, DaemonReloadPort, DaemonReloadScope};
use crate::{
    models::audit::{AuditEvent, AuditEventKind, ConfigAction},
    services::config::ConfigService,
    utils::{
        config_reload::{has_firewall_runtime_change, has_proc_runtime_change, log_config_delta},
        notification_reply::{send_notification_reply, status_payload},
    },
};

impl CommandControlService {
    pub(crate) async fn apply_config(
        &self,
        notification_id: u64,
        raw_json: String,
        config: &ConfigService,
        task_reply_tx: &tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
        daemon_reload: &dyn DaemonReloadPort,
    ) {
        tracing::debug!(notification_id, "received apply-config command");
        let previous = config.get_snapshot();
        let updated = match config.parse_raw_json(&raw_json).await {
            Ok(updated) => updated,
            Err(err) => {
                tracing::error!("failed to apply config update: {err}");
                let _ = send_notification_reply(
                    task_reply_tx,
                    notification_id,
                    transport_wire_core::WireNotificationReplyCode::Error,
                    format!("failed to apply config update: {err}"),
                    CONTROL_COMMAND_NOTIFICATION_LABEL,
                )
                .await;
                return;
            }
        };

        let reload_proc = has_proc_runtime_change(&previous, &updated);
        let reload_fw = has_firewall_runtime_change(&previous, &updated, false);

        log_config_delta(&previous, &updated, false);
        tracing::info!(
            notification_id,
            addr = %updated.client_addr,
            log_level = updated.log_level,
            ?updated.default_action,
            ?updated.proc_monitor_method,
            ?updated.firewall_backend,
            "applying config update to runtime services"
        );

        if let Err(err) = daemon_reload
            .daemon_reload(
                &updated,
                Some(DaemonReloadScope {
                    services: self.selective_reload_services(reload_proc, reload_fw),
                }),
            )
            .await
        {
            tracing::error!("config update failed during daemon reload: {err}");
            self.audit
                .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                    ConfigAction::UpdateFailed {
                        reason: format!("reload: {err}").into(),
                    },
                )));
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                format!("config update failed: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }

        if (reload_proc || reload_fw) && updated.flush_conns_on_start {
            crate::utils::config_reload::flush_established_connections().await;
        } else {
            tracing::debug!("[config] not flushing established connections");
        }

        if let Err(err) = config.persist_raw_json(&raw_json).await {
            tracing::error!("failed to persist config payload after runtime apply: {err}");
            self.audit
                .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                    ConfigAction::UpdateFailed {
                        reason: format!("persist: {err}").into(),
                    },
                )));
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                format!("failed to persist config payload after runtime apply: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }
        config.set_snapshot(updated.clone()).await;
        tracing::info!(notification_id, "config update applied successfully");
        self.audit
            .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                ConfigAction::ConfigApplied,
            )));
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            transport_wire_core::WireNotificationReplyCode::Ok,
            status_payload("ok"),
            CONTROL_COMMAND_NOTIFICATION_LABEL,
        )
        .await;
    }

    pub(crate) async fn set_log_level(
        &self,
        notification_id: u64,
        level: i32,
        config: &ConfigService,
        task_reply_tx: &tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    ) {
        if !self.is_valid_log_level(level) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                format!("invalid log level: {level}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }

        let mapped_level = if level < 0 { 0 } else { level as u32 };
        config.set_log_level(mapped_level).await;
        let snapshot = config.get_snapshot();
        if let Err(err) = crate::logging::LoggingState::apply_config(&snapshot) {
            let _ = send_notification_reply(
                task_reply_tx,
                notification_id,
                transport_wire_core::WireNotificationReplyCode::Error,
                format!("failed to apply runtime log level: {err}"),
                CONTROL_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            return;
        }
        tracing::info!(level, "updated daemon log level setting");
        self.audit
            .emit(AuditEvent::cold(AuditEventKind::ConfigAction(
                ConfigAction::FieldUpdated { key: "log_level" },
            )));
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            transport_wire_core::WireNotificationReplyCode::Ok,
            transport_wire_core::status_with_log_level_payload("ok", level),
            CONTROL_COMMAND_NOTIFICATION_LABEL,
        )
        .await;
    }
}
