use std::{
    collections::HashSet,
    sync::{Arc, OnceLock, RwLock},
    thread,
    thread::JoinHandle,
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::platform::adapters::net_iface::NetIfaceAdapter;
use crate::workers::runtime::support::build_current_thread_runtime;

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

static LOCAL_ADDRS: OnceLock<RwLock<Arc<Vec<String>>>> = OnceLock::new();

pub(crate) struct NetlinkAddrWorkerControl;

impl NetlinkAddrWorkerControl {
    fn local_addr_store() -> &'static RwLock<Arc<Vec<String>>> {
        LOCAL_ADDRS.get_or_init(|| RwLock::new(Arc::new(Vec::new())))
    }

    pub fn spawn(shutdown: CancellationToken) -> JoinHandle<()> {
        thread::spawn(move || {
            let Some(runtime) =
                build_current_thread_runtime("unable to build local address runtime")
            else {
                return;
            };

            runtime.block_on(async move {
                while !shutdown.is_cancelled() {
                    match Self::fetch_local_addrs().await {
                        Ok(latest) => {
                            let previous_snapshot = {
                                let guard = Self::local_addr_store()
                                    .read()
                                    .expect("local addr read lock poisoned");
                                Arc::clone(&guard)
                            };
                            let previous: HashSet<String> =
                                previous_snapshot.iter().cloned().collect();

                            for added in latest.difference(&previous) {
                                debug!(address = %added, "local address added");
                            }
                            for removed in previous.difference(&latest) {
                                debug!(address = %removed, "local address removed");
                            }

                            let mut latest_sorted: Vec<String> = latest.into_iter().collect();
                            latest_sorted.sort();

                            let mut guard = Self::local_addr_store()
                                .write()
                                .expect("local addr write lock poisoned");
                            *guard = Arc::new(latest_sorted);
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn snapshot_local_addrs() -> Vec<String> {
        let guard = Self::local_addr_store()
            .read()
            .expect("local addr read lock poisoned");
        guard.as_ref().clone()
    }

    async fn fetch_local_addrs() -> anyhow::Result<HashSet<String>> {
        // Keep behavior close to Go by enumerating local addresses without
        // strict netlink attribute parsing that can emit noisy kernel-version warnings.
        NetIfaceAdapter::local_ip_addrs_async().await
    }
}
