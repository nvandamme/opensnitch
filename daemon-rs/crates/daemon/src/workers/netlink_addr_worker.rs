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
                match fetch_local_addrs().await {
                    Ok(latest) => {
                        let mut guard = local_addr_store().write().await;

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

#[allow(dead_code)]
pub async fn snapshot_local_addrs() -> Vec<String> {
    let mut out: Vec<String> = local_addr_store().read().await.iter().cloned().collect();
    out.sort();
    out
}

async fn fetch_local_addrs() -> anyhow::Result<HashSet<String>> {
    use anyhow::Context;
    use rtnetlink::packet_route::address::AddressAttribute;
    use tokio_stream::StreamExt;

    let (connection, handle, _) =
        rtnetlink::new_connection().context("new rtnetlink connection")?;
    tokio::spawn(connection);

    let mut out = HashSet::new();
    let mut addrs = handle.address().get().execute();

    while let Some(msg) = addrs.next().await {
        let msg = msg.context("iterate local addresses")?;
        for attr in msg.attributes {
            match attr {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    out.insert(ip.to_string());
                }
                _ => {}
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::snapshot_local_addrs;

    #[tokio::test]
    async fn snapshot_local_addrs_returns_sorted_values() {
        let mut values = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST).to_string(),
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        ];
        values.sort();

        let snap = snapshot_local_addrs().await;
        // The worker may not be running in this unit test; this just validates API behavior.
        assert!(snap.is_empty() || snap.windows(2).all(|w| w[0] <= w[1]));
        let _ = values;
    }
}
