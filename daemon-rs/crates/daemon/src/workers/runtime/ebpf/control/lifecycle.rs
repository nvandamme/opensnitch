use super::*;

#[cfg(test)]
#[path = "../../../../tests/workers/ebpf_control_lifecycle_probe_support.rs"]
mod ebpf_control_lifecycle_probe_support;

impl EbpfWorkerMode {
    // Convenience mode constant retained for generic worker initialization paths.
    #[allow(dead_code)]
    pub(crate) const ALL: Self = Self {
        enable_dns: true,
        enable_proc: true,
        enable_conn: true,
    };

    pub(crate) const DNS_ONLY: Self = Self {
        enable_dns: true,
        enable_proc: false,
        enable_conn: false,
    };

    pub(crate) const PROC_ONLY: Self = Self {
        enable_dns: false,
        enable_proc: true,
        enable_conn: false,
    };

    pub(crate) const CONN_ONLY: Self = Self {
        enable_dns: false,
        enable_proc: false,
        enable_conn: true,
    };

    fn native_ringbuf_requested(&self) -> bool {
        self.enable_proc || self.enable_dns
    }
}

pub struct EbpfWorkerControl {
    bus: Bus,
    daemon_shutdown: CancellationToken,
    prune_policy: EbpfMapPrunePolicy,
    mode: EbpfWorkerMode,
    worker_name: &'static str,
    runtime: Mutex<EbpfWorkerRuntime>,
}

impl EbpfWorkerControl {
    // Constructor retained for API parity; some profiles construct via new_with_mode.
    #[allow(dead_code)]
    pub fn new(bus: Bus, daemon_shutdown: CancellationToken, tunables: RuntimeTunables) -> Self {
        Self::new_with_mode(bus, daemon_shutdown, tunables, EbpfWorkerMode::ALL, "ebpf")
    }

    pub(crate) fn new_with_mode(
        bus: Bus,
        daemon_shutdown: CancellationToken,
        tunables: RuntimeTunables,
        mode: EbpfWorkerMode,
        worker_name: &'static str,
    ) -> Self {
        let worker_shutdown = daemon_shutdown.child_token();
        let prune_policy = EbpfMapPrunePolicy::from_tunables(tunables);
        let handle = Self::spawn_worker_thread(
            bus.clone(),
            worker_shutdown.clone(),
            prune_policy,
            mode,
            worker_name,
        );
        Self {
            bus,
            daemon_shutdown,
            prune_policy,
            mode,
            worker_name,
            runtime: Mutex::new(EbpfWorkerRuntime {
                shutdown: worker_shutdown,
                handle: Some(handle),
            }),
        }
    }

    fn stop_worker(&self) -> WorkerCommandResult {
        if let Ok(runtime) = self.runtime.lock() {
            runtime.shutdown.cancel();
            WorkerCommandResult::Applied
        } else {
            WorkerCommandResult::Unsupported
        }
    }

    fn start_worker(&self) -> WorkerCommandResult {
        if self.daemon_shutdown.is_cancelled() {
            return WorkerCommandResult::Unsupported;
        }

        let Ok(mut runtime) = self.runtime.lock() else {
            return WorkerCommandResult::Unsupported;
        };

        let needs_start = runtime
            .handle
            .as_ref()
            .is_none_or(|handle| handle.is_finished());

        if needs_start {
            if let Some(handle) = runtime.handle.take() {
                let _ = handle.join();
            }

            runtime.shutdown = self.daemon_shutdown.child_token();
            runtime.handle = Some(Self::spawn_worker_thread(
                self.bus.clone(),
                runtime.shutdown.clone(),
                self.prune_policy,
                self.mode,
                self.worker_name,
            ));
        }

        WorkerCommandResult::Applied
    }

    fn spawn_worker_thread(
        bus: Bus,
        shutdown: CancellationToken,
        prune_policy: EbpfMapPrunePolicy,
        mode: EbpfWorkerMode,
        worker_name: &'static str,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            info!(
                worker = worker_name,
                enabled = mode.enable_conn || mode.enable_proc || mode.enable_dns,
                ringbuf_requested = mode.native_ringbuf_requested(),
                "eBPF worker facilities requested"
            );

            let mut runtime = match EbpfService::load_existing_objects() {
                Ok(runtime) => {
                    debug!(
                        pin_domain = ?runtime.pin_domain(),
                        conn_obj = ?runtime.conn_obj,
                        proc_obj = ?runtime.proc_obj,
                        process_obj = ?runtime.process_obj,
                        dns_obj = ?runtime.dns_obj,
                        rust_dns_obj = ?runtime.rust_dns_obj,
                        "eBPF object discovery initialized"
                    );
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcessMapHit {
                            pid: std::process::id(),
                            uid: 0,
                            note: "eBPF object discovery active".into(),
                        },
                    );
                    Some(runtime)
                }
                Err(err) => {
                    warn!(worker = worker_name, "eBPF runtime not available: {err}");
                    None
                }
            };

            if mode.enable_dns
                && !mode.enable_proc
                && !mode.enable_conn
                && let Some(runtime) = runtime.as_ref()
                && let Some(explicit_runtime) = Self::select_dns_explicit_runtime(runtime)
            {
                match Self::run_dns_explicit_runtime(&bus, &shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit DNS eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        let summary = Self::summarize_bpf_attach_error(&err);
                        warn!(
                            worker = worker_name,
                            detail = %summary,
                            "explicit DNS eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                        debug!(
                            worker = worker_name,
                            detail = %err,
                            "explicit DNS eBPF attach/runtime full verifier output"
                        );
                    }
                }
            }

            if mode.enable_proc
                && !mode.enable_dns
                && !mode.enable_conn
                && let Some(runtime) = runtime.as_ref()
                && let Some(explicit_runtime) = Self::select_proc_explicit_runtime(runtime)
            {
                match Self::run_proc_explicit_runtime(&bus, &shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit process eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        warn!(
                            worker = worker_name,
                            detail = %err,
                            "explicit process eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                    }
                }
            }

            if mode.enable_conn
                && !mode.enable_dns
                && !mode.enable_proc
                && let Some(runtime) = runtime.as_ref()
                && let Some(explicit_runtime) = Self::select_conn_explicit_runtime(runtime)
            {
                match Self::run_conn_explicit_runtime(&shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(
                            worker = worker_name,
                            "explicit connection eBPF runtime active"
                        );
                        return;
                    }
                    Err(err) => {
                        warn!(
                            worker = worker_name,
                            detail = %err,
                            "explicit connection eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                    }
                }
            }

            if let Some(runtime) = runtime.as_mut() {
                Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
                #[cfg(feature = "aya-ebpf")]
                runtime.refresh_aya_managed_ringbufs();
            }

            let mut state = SupervisorState::default();
            let mut native_ringbuf = if mode.native_ringbuf_requested() {
                let pin_domain = runtime
                    .as_ref()
                    .map(|runtime| runtime.pin_domain())
                    .unwrap_or_else(EbpfService::selected_pin_domain);
                #[cfg(feature = "aya-ebpf")]
                let managed_aya_ringbuf = runtime.as_mut().and_then(|runtime| {
                    runtime.take_aya_managed_ringbuf(mode.enable_proc, mode.enable_dns)
                });

                match NativeRingbuf::try_open(
                    mode,
                    worker_name,
                    pin_domain,
                    #[cfg(feature = "aya-ebpf")]
                    managed_aya_ringbuf,
                ) {
                    Ok((consumer, diagnostics)) => {
                        for detail in diagnostics {
                            info!(worker = worker_name, detail = %detail, "native eBPF ringbuf backend fallback detail");
                        }

                        info!(
                            worker = worker_name,
                            runtime_mode = ?consumer.runtime_mode(),
                            backend = ?consumer.backend_kind(),
                            "native eBPF ringbuf consumer enabled"
                        );

                        let _ = crate::workers::dispatch_kernel_event_with_backoff(
                            &bus.kernel_tx,
                            KernelEvent::EbpfProcessMapHit {
                                pid: std::process::id(),
                                uid: 0,
                                note: "native eBPF ringbuf consumer enabled".into(),
                            },
                        );
                        Some(consumer)
                    }
                    Err(err) => {
                        warn!(worker = worker_name, detail = %err, "native eBPF ringbuf consumer unavailable");
                        None
                    }
                }
            } else {
                info!(
                    worker = worker_name,
                    "native eBPF ringbuf not requested for this worker mode"
                );
                None
            };

            let active = mode.enable_conn || mode.enable_proc || mode.enable_dns;
            match (mode.enable_conn, mode.enable_proc, mode.enable_dns) {
                (true, false, false) => {
                    info!(
                        worker = worker_name,
                        conn_active = true,
                        "eBPF worker facilities active"
                    );
                }
                (false, true, false) => {
                    info!(
                        worker = worker_name,
                        proc_ringbuf_active = native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
                (false, false, true) => {
                    info!(
                        worker = worker_name,
                        dns_ringbuf_active = native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
                _ => {
                    info!(
                        worker = worker_name,
                        active,
                        conn_active = mode.enable_conn,
                        proc_ringbuf_active = mode.enable_proc && native_ringbuf.is_some(),
                        dns_ringbuf_active = mode.enable_dns && native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
            }

            let mut last_conn_supervise = Instant::now()
                .checked_sub(CONN_SUPERVISE_INTERVAL)
                .unwrap_or_else(Instant::now);
            if mode.enable_conn {
                Self::supervise_runtime(&bus, &mut state, prune_policy);
                last_conn_supervise = Instant::now();
            }

            let mut last_reconcile = Instant::now();

            while !shutdown.is_cancelled() {
                if let Some(consumer) = native_ringbuf.as_mut()
                    && let Err(err) = consumer.poll_and_emit(&bus)
                {
                    warn!(
                        worker = worker_name,
                        "native eBPF ringbuf poll failed, disabling consumer: {err}"
                    );
                    native_ringbuf = None;
                }

                if last_reconcile.elapsed() >= Duration::from_secs(30) {
                    if let Some(runtime) = runtime.as_mut() {
                        Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
                        #[cfg(feature = "aya-ebpf")]
                        runtime.refresh_aya_managed_ringbufs();
                    }
                    last_reconcile = Instant::now();
                }

                if mode.enable_conn && last_conn_supervise.elapsed() >= CONN_SUPERVISE_INTERVAL {
                    Self::supervise_runtime(&bus, &mut state, prune_policy);
                    last_conn_supervise = Instant::now();
                }

                let active_ringbuf =
                    native_ringbuf.is_some() && (mode.enable_proc || mode.enable_dns);
                let loop_delay = if active_ringbuf {
                    EBPFRING_ACTIVE_LOOP_INTERVAL
                } else {
                    CONN_SUPERVISE_INTERVAL
                };
                if crate::workers::sleep_with_shutdown(
                    &shutdown,
                    loop_delay,
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
            }
        })
    }
    fn summarize_bpf_attach_error(err: &str) -> String {
        let mut summary = err;
        if let Some((head, _)) = err.split_once("Verifier output:") {
            summary = head.trim();
        }
        if let Some((line, _)) = summary.split_once('\n') {
            summary = line.trim();
        }
        summary.to_string()
    }
}

impl_restartable_thread_worker_control!(EbpfWorkerControl, "ebpf");
