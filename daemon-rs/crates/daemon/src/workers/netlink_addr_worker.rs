use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
    thread,
    thread::JoinHandle,
    time::Duration,
};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

static LOCAL_ADDRS: OnceLock<Arc<RwLock<HashSet<String>>>> = OnceLock::new();

pub(crate) struct NetlinkAddrWorkerControl;

impl NetlinkAddrWorkerControl {
    fn local_addr_store() -> &'static Arc<RwLock<HashSet<String>>> {
        LOCAL_ADDRS.get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
    }

    pub fn spawn(shutdown: CancellationToken) -> JoinHandle<()> {
        thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                warn!("unable to build local address runtime");
                return;
            };

            runtime.block_on(async move {
                while !shutdown.is_cancelled() {
                    match Self::fetch_local_addrs().await {
                        Ok(latest) => {
                            let mut guard = Self::local_addr_store().write().await;

                            for added in latest.difference(&guard) {
                                debug!(address = %added, "local address added");
                            }
                            for removed in guard.difference(&latest) {
                                debug!(address = %removed, "local address removed");
                            }

                            *guard = latest;
                        }
                        Err(err) => {
                            warn!("failed to refresh local address snapshot: {err}");
                        }
                    }

                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(REFRESH_INTERVAL) => {}
                    }
                }
            });
        })
    }

    #[cfg(test)]
    pub async fn snapshot_local_addrs() -> Vec<String> {
        let mut out: Vec<String> = Self::local_addr_store()
            .read()
            .await
            .iter()
            .cloned()
            .collect();
        out.sort();
        out
    }

    async fn fetch_local_addrs() -> anyhow::Result<HashSet<String>> {
        // Keep behavior close to Go by enumerating local addresses without
        // strict netlink attribute parsing that can emit noisy kernel-version warnings.
        Ok(crate::utils::net_iface::local_ip_addrs())
    }
}
