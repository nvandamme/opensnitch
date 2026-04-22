use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    thread,
    thread::JoinHandle,
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::platform::ports::local_addr_port::LocalAddrPort;
use crate::workers::runtime::support::build_current_thread_runtime;

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) type LocalAddrStore = Arc<RwLock<Arc<Vec<String>>>>;

pub(crate) struct NetlinkAddrWorkerControl;

impl NetlinkAddrWorkerControl {
    fn new_local_addr_store() -> LocalAddrStore {
        Arc::new(RwLock::new(Arc::new(Vec::new())))
    }

    pub fn spawn(shutdown: CancellationToken) -> (JoinHandle<()>, LocalAddrStore) {
        let local_addr_store = Self::new_local_addr_store();
        let local_addr_store_for_worker = Arc::clone(&local_addr_store);

        let handle = thread::spawn(move || {
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
                                let guard = local_addr_store_for_worker
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

                            let mut guard = local_addr_store_for_worker
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
        });

        (handle, local_addr_store)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn snapshot_local_addrs(local_addr_store: &LocalAddrStore) -> Vec<String> {
        let guard = local_addr_store
            .read()
            .expect("local addr read lock poisoned");
        guard.as_ref().clone()
    }

    async fn fetch_local_addrs() -> anyhow::Result<HashSet<String>> {
        LocalAddrPort::local_ip_addrs().await
    }
}
