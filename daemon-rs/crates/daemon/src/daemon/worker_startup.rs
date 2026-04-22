use tracing::{debug, info, warn};

use super::Daemon;
use crate::{
    config::ProcMonitorMethod,
    flows::lifecycle::ServiceLifecycleFlow,
    services::ebpf::EbpfService,
    workers::{self, runtime::control::RuntimeHandles},
};

impl Daemon {
    pub(super) async fn spawn_workers(&self, handles: &mut RuntimeHandles) {
        info!("starting worker set");
        ServiceLifecycleFlow::new(self.inner.shutdown.clone()).spawn_observers(
            handles,
            &self.inner.connections,
            &self.inner.process,
            &self.inner.dns,
            &self.inner.firewall,
        );
        handles.push_worker_control(Self::boxed_one_shot_worker(self.proc_workers_control()));

        handles.push_worker(
            "nfqueue",
            workers::runtime::nfqueue::worker::NfqueueWorkerControl::spawn(
                self.inner.bus.clone(),
                self.inner.nfqueue_num,
                self.inner.default_action,
                self.inner.tunables.nfqueue_overload_policy,
                self.inner.shutdown.clone(),
            ),
        );
        debug!(queue = self.inner.nfqueue_num, "nfqueue worker started");

        let requested_method = self.inner.config.get_snapshot().proc_monitor_method;
        let ebpf_availability = EbpfService::probe_availability();
        let preferred_method = self
            .inner
            .process
            .preferred_monitor_method(requested_method, ebpf_availability);

        if requested_method == ProcMonitorMethod::Ebpf && preferred_method != requested_method {
            warn!("eBPF proc intent unavailable, falling back to netlink proc monitor");
        }

        if let Err(err) = self.reconfigure_proc_workers(Some(preferred_method)).await {
            warn!(method = ?preferred_method, "failed to start requested process monitor method: {err}");
            let _ = self
                .reconfigure_proc_workers(Some(ProcMonitorMethod::Proc))
                .await;
        }

        let proc_snapshot = self.proc_workers_snapshot();
        let process_worker_state = self.inner.process.worker_state();
        let ebpf_proc_active =
            proc_snapshot.method == ProcMonitorMethod::Ebpf && proc_snapshot.running_handles > 0;

        info!(
            requested_method = ?requested_method,
            preferred_method = ?preferred_method,
            effective_method = ?proc_snapshot.method,
            worker_requested_method = ?process_worker_state.requested_method,
            worker_count = process_worker_state.worker_count,
            ebpf_process_available = ebpf_availability.process_available,
            ebpf_dns_available = ebpf_availability.dns_available,
            "process monitor preference resolved"
        );

        if ebpf_proc_active {
            info!("process fallback worker skipped: eBPF proc worker active");
        }

        let conn_workers = self.inner.connections.init_workers(
            self.inner.bus.clone(),
            self.inner.shutdown.clone(),
            self.inner.tunables,
            ebpf_availability,
        );
        let conn_state = self.inner.connections.worker_state();
        let conn_workers_count = conn_workers.len();
        if conn_workers.is_empty() {
            warn!(
                "eBPF conn intent unavailable, using socket-diag/proc resolver fallback path for connection owner enrichment"
            );
        } else {
            for worker in conn_workers {
                handles.push_worker_control(worker);
            }
            debug!("connection intent workers started");
        }
        debug!(
            worker_kind = ?conn_state.worker_kind,
            worker_count = conn_workers_count,
            "connection intent worker selection resolved"
        );

        let dns_workers = self.inner.dns.init_workers(
            self.inner.bus.clone(),
            self.inner.shutdown.clone(),
            self.inner.tunables,
            ebpf_availability,
        );
        let dns_state = self.inner.dns.worker_state();
        let dns_workers_count = dns_workers.len();
        if matches!(
            dns_state.worker_kind,
            crate::services::dns::DnsWorkerKind::Fallback
        ) {
            warn!("eBPF dns intent unavailable, enabling DNS fallback worker");
        }
        for worker in dns_workers {
            handles.push_worker_control(worker);
        }
        debug!(
            worker_kind = ?dns_state.worker_kind,
            worker_count = dns_workers_count,
            "dns intent worker selection resolved"
        );
        debug!("dns intent workers started");

        handles.push_worker(
            "firewall",
            workers::firewall::firewall_worker::FirewallWorkerControl::spawn(
                self.inner.bus.clone(),
                self.inner.firewall.clone(),
                self.inner.shutdown.clone(),
            ),
        );
        debug!("firewall worker started");

        handles.push_worker(
            "netlink-ifaces",
            workers::network::netlink_addr_worker::NetlinkAddrWorkerControl::spawn(
                self.inner.shutdown.clone(),
            ),
        );
        debug!("netlink local-address worker started");
    }
}
