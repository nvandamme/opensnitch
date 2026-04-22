use tracing::{debug, info, warn};

use super::Daemon;
use crate::{
    config::ProcMonitorMethod,
    flows::lifecycle::ServiceLifecycleFlow,
    models::audit::{
        AuditEvent, AuditEventKind, ConnectionLifecycle, DnsLifecycle, FirewallLifecycle,
        ProcessLifecycle, ServiceObserverLifecycle,
    },
    services::ebpf::EbpfService,
    workers::{
        self,
        runtime::control::{RuntimeHandles, WorkerControl},
    },
};

impl Daemon {
    pub(super) async fn spawn_workers(&self, handles: &mut RuntimeHandles) {
        info!("starting worker set");
        ServiceLifecycleFlow::new(self.runtime.shutdown.clone()).spawn_observers(
            handles,
            &self.runtime.connections,
            &self.runtime.process,
            &self.runtime.dns,
            &self.runtime.firewall,
        );
        self.runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ServiceObserverLifecycle(
                ServiceObserverLifecycle::ServiceObserversStarted,
            )));
        handles.push_worker_control(self.proc_workers_control().into_worker_control());

        handles.push_worker(
            "nfqueue",
            workers::runtime::nfqueue::worker::NfqueueWorkerControl::spawn(
                self.runtime.bus.clone(),
                self.runtime.nfqueue_num,
                self.runtime.default_action,
                self.runtime.tunables.nfqueue_overload_policy,
                self.runtime.shutdown.clone(),
            ),
        );
        debug!(queue = self.runtime.nfqueue_num, "nfqueue worker started");

        let requested_method = self.runtime.config.get_snapshot().proc_monitor_method;
        let ebpf_availability = EbpfService::probe_availability();
        let preferred_method = self
            .runtime
            .process
            .preferred_monitor_method(requested_method, ebpf_availability);

        if requested_method == ProcMonitorMethod::Ebpf && preferred_method != requested_method {
            warn!("eBPF process worker unavailable, falling back to netlink proc monitor");
        }

        if let Err(err) = self.reconfigure_proc_workers(Some(preferred_method)).await {
            warn!(method = ?preferred_method, "failed to start requested process monitor method: {err}");
            let _ = self
                .reconfigure_proc_workers(Some(ProcMonitorMethod::Proc))
                .await;
        }
        self.runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ProcessLifecycle(
                ProcessLifecycle::MonitorWorkersConfigured,
            )));

        let proc_snapshot = self.proc_workers_snapshot();
        let process_worker_state = self.runtime.process.worker_state();
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

        let conn_workers = self.runtime.connections.init_workers(
            self.runtime.bus.clone(),
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            ebpf_availability,
        );
        let conn_state = self.runtime.connections.worker_state();
        let conn_workers_count = conn_workers.len();
        if conn_workers.is_empty() {
            warn!(
                "eBPF connection worker unavailable, using socket-diag/proc resolver fallback path for connection owner enrichment"
            );
        } else {
            for worker in conn_workers {
                handles.push_worker_control(worker);
            }
            debug!("connection workers started");
        }
        debug!(
            worker_kind = ?conn_state.worker_kind,
            worker_count = conn_workers_count,
            "connection worker selection resolved"
        );
        self.runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ConnectionLifecycle(
                ConnectionLifecycle::WorkersConfigured,
            )));

        let dns_workers = self.runtime.dns.init_workers(
            self.runtime.bus.clone(),
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            ebpf_availability,
        );
        let dns_state = self.runtime.dns.worker_state();
        let dns_workers_count = dns_workers.len();
        if matches!(
            dns_state.worker_kind,
            crate::services::dns::DnsWorkerKind::Fallback
        ) {
            warn!("eBPF DNS worker unavailable, enabling DNS fallback worker");
        }
        for worker in dns_workers {
            handles.push_worker_control(worker);
        }
        debug!(
            worker_kind = ?dns_state.worker_kind,
            worker_count = dns_workers_count,
            "dns worker selection resolved"
        );
        debug!("dns workers started");
        self.runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::DnsLifecycle(
                DnsLifecycle::WorkersConfigured,
            )));

        handles.push_worker(
            "firewall",
            workers::firewall::firewall_worker::FirewallWorkerControl::spawn(
                self.runtime.bus.clone(),
                self.runtime.firewall.clone(),
                self.runtime.rules.clone(),
                self.runtime.shutdown.clone(),
            ),
        );
        debug!("firewall worker started");
        self.runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::FirewallLifecycle(
                FirewallLifecycle::WorkerStarted,
            )));

        let (netlink_ifaces_handle, _netlink_local_addr_store) =
            workers::network::netlink_addr_worker::NetlinkAddrWorkerControl::spawn(
                self.runtime.shutdown.clone(),
            );
        handles.push_worker("netlink-ifaces", netlink_ifaces_handle);
        debug!("netlink local-address worker started");
    }
}
