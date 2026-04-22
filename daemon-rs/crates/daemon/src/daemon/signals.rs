use anyhow::Result;
use tracing::{info, warn};

use super::Daemon;
use crate::utils::systemd_notify::{NotifyState, notify};

impl Daemon {
    pub(super) async fn run_signal_loop(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sig_int = signal(SignalKind::interrupt())?;
            let mut sig_term = signal(SignalKind::terminate())?;
            let mut sig_hup = signal(SignalKind::hangup())?;

            loop {
                tokio::select! {
                    _ = self.inner.shutdown.cancelled() => {
                        info!("shutdown requested");
                        notify(NotifyState::Status("Shutdown requested by runtime command"));
                        break;
                    }
                    signal = sig_int.recv() => {
                        if signal.is_some() {
                            info!("SIGINT received");
                            notify(NotifyState::Status("SIGINT received, stopping daemon"));
                        } else {
                            warn!("SIGINT stream closed");
                        }
                        break;
                    }
                    signal = sig_term.recv() => {
                        if signal.is_some() {
                            info!("SIGTERM received");
                            notify(NotifyState::Status("SIGTERM received, stopping daemon"));
                        } else {
                            warn!("SIGTERM stream closed");
                        }
                        break;
                    }
                    signal = sig_hup.recv() => {
                        if signal.is_none() {
                            warn!("SIGHUP stream closed");
                            continue;
                        }
                        self.reload_runtime_after_sighup().await;
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl-c received");
                }
                _ = self.inner.shutdown.cancelled() => {
                    info!("shutdown requested");
                }
            }
        }

        Ok(())
    }
}
