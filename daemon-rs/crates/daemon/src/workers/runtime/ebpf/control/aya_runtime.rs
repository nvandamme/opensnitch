// Aya explicit-runtime helpers are retained for aya-enabled profiles.
#![cfg(feature = "aya-ebpf")]

use super::*;

impl EbpfWorkerControl {
    #[cfg(feature = "aya-ebpf")]
    pub(super) fn run_dns_explicit_aya_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        dns_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{
            EbpfLoader,
            maps::{Map, RingBuf},
            programs::UProbe,
        };

        let libc =
            Self::find_libc_path().ok_or_else(|| "failed to resolve libc path".to_string())?;
        let mut bpf = EbpfLoader::new()
            .load_file(dns_obj)
            .map_err(|err| format!("load Rust DNS object failed ({}): {err}", dns_obj.display()))?;

        let mut attached = 0usize;
        for spec in Self::dns_uprobe_specs() {
            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                let available = bpf
                    .programs()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    available = %available,
                    "explicit Rust DNS program not found in object; skipping"
                );
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                warn!(
                    program = spec.program_name,
                    key = lookup_key,
                    "explicit Rust DNS program handle disappeared; skipping"
                );
                continue;
            };

            let program: &mut UProbe = match program_handle.try_into() {
                Ok(program) => program,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        detail = %err,
                        "explicit Rust DNS program type mismatch; skipping"
                    );
                    continue;
                }
            };

            if let Err(err) = program.load() {
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    detail = %err,
                    "explicit Rust DNS program load failed"
                );
                continue;
            }

            match program.attach(Some(spec.symbol_name), 0, &libc, None) {
                Ok(_) => attached += 1,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        symbol = spec.symbol_name,
                        detail = %err,
                        "explicit Rust DNS uprobe attach failed"
                    );
                }
            }
        }

        if attached == 0 {
            return Err("no Rust DNS uprobes attached".to_string());
        }

        if let Some(events_dir) = Path::new(EbpfPinDomain::Aya.dns_events_path()).parent() {
            let _ = fs::create_dir_all(events_dir);
        }
        if !Path::new(EbpfPinDomain::Aya.dns_events_path()).exists() {
            bpf.map_mut(EVENTS_MAP_NAME)
                .ok_or_else(|| format!("Rust DNS object map '{}' not found", EVENTS_MAP_NAME))?
                .pin(EbpfPinDomain::Aya.dns_events_path())
                .map_err(|err| format!("pin Rust DNS events map failed: {err}"))?;
        }

        let map = bpf
            .take_map(EVENTS_MAP_NAME)
            .ok_or_else(|| format!("Rust DNS object map '{}' not found", EVENTS_MAP_NAME))?;
        let map = match map {
            Map::RingBuf(map) => Map::RingBuf(map),
            _ => {
                return Err(format!(
                    "Rust DNS object map '{}' is not a ringbuf",
                    EVENTS_MAP_NAME
                ));
            }
        };
        let mut ringbuf = RingBuf::try_from(map)
            .map_err(|err| format!("Rust DNS ringbuf reader attach failed: {err}"))?;

        let mut dns_deduper = DnsEbpfEventDeduper::default();
        while !shutdown.is_cancelled() {
            let samples = {
                let mut out = Vec::with_capacity(64);
                while let Some(item) = ringbuf.next() {
                    out.push(item.to_vec());
                }
                out
            };

            if samples.is_empty() {
                if crate::workers::sleep_with_shutdown(
                    shutdown,
                    Duration::from_millis(100),
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
                continue;
            }

            for sample in samples {
                let Some(payload) = DnsService::parse_ebpf_dns_sample(&sample) else {
                    continue;
                };
                if !dns_deduper.should_emit(&payload) {
                    continue;
                }
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::DnsUpdate(payload),
                );
            }
        }

        drop(ringbuf);
        drop(bpf);
        Ok(())
    }

    #[cfg(feature = "aya-ebpf")]
    pub(super) fn run_proc_explicit_aya_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        proc_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{
            EbpfLoader,
            maps::{Map, RingBuf},
            programs::TracePoint,
        };

        let mut bpf = EbpfLoader::new().load_file(proc_obj).map_err(|err| {
            format!(
                "load Rust process object failed ({}): {err}",
                proc_obj.display()
            )
        })?;

        let mut attached = 0usize;
        for spec in Self::proc_tracepoint_specs() {
            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                let available = bpf
                    .programs()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    available = %available,
                    "explicit Rust process program not found in object; skipping"
                );
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                warn!(
                    program = spec.program_name,
                    key = lookup_key,
                    "explicit Rust process program handle disappeared; skipping"
                );
                continue;
            };

            let program: &mut TracePoint = match program_handle.try_into() {
                Ok(program) => program,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        detail = %err,
                        "explicit Rust process program type mismatch; skipping"
                    );
                    continue;
                }
            };

            program.load().map_err(|err| {
                format!(
                    "load Rust process program '{}' failed ({}): {err}",
                    spec.program_name,
                    proc_obj.display()
                )
            })?;

            match program.attach(spec.category, spec.name) {
                Ok(_) => attached += 1,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        category = spec.category,
                        name = spec.name,
                        detail = %err,
                        "explicit Rust process tracepoint attach failed"
                    );
                }
            }
        }

        if attached == 0 {
            return Err("no Rust process tracepoints attached".to_string());
        }

        info!(
            worker = "ebpf-proc",
            attached, "explicit process tracepoints attached"
        );

        let _ = crate::workers::dispatch_kernel_event_with_backoff(
            &bus.kernel_tx,
            KernelEvent::EbpfProcessMapHit {
                pid: std::process::id(),
                uid: 0,
                note: format!("explicit process tracepoints attached count={attached}"),
            },
        );

        if let Some(events_dir) = Path::new(EbpfPinDomain::Aya.proc_events_path()).parent() {
            let _ = fs::create_dir_all(events_dir);
        }
        if !Path::new(EbpfPinDomain::Aya.proc_events_path()).exists() {
            bpf.map_mut(EVENTS_MAP_NAME)
                .ok_or_else(|| format!("Rust process object map '{}' not found", EVENTS_MAP_NAME))?
                .pin(EbpfPinDomain::Aya.proc_events_path())
                .map_err(|err| format!("pin Rust process events map failed: {err}"))?;
        }

        let map = bpf
            .take_map(EVENTS_MAP_NAME)
            .ok_or_else(|| format!("Rust process object map '{}' not found", EVENTS_MAP_NAME))?;
        let map = match map {
            Map::RingBuf(map) => Map::RingBuf(map),
            _ => {
                return Err(format!(
                    "Rust process object map '{}' is not a ringbuf",
                    EVENTS_MAP_NAME
                ));
            }
        };
        let mut ringbuf = RingBuf::try_from(map)
            .map_err(|err| format!("Rust process ringbuf reader attach failed: {err}"))?;

        let mut total_samples: usize = 0;
        let mut parsed_samples: usize = 0;
        let mut rejected_samples: usize = 0;
        let mut first_payload_logged = false;
        let mut last_stats_emit = Instant::now();

        while !shutdown.is_cancelled() {
            let mut samples = 0usize;
            while let Some(item) = ringbuf.next() {
                samples += 1;
                total_samples = total_samples.saturating_add(1);
                trace!(
                    sample_len = item.len(),
                    worker = "ebpf-proc",
                    "explicit process ringbuf sample received"
                );
                if let Some(payload) = ProcessService::parse_ebpf_proc_state_payload(&item) {
                    debug!(
                        worker = "ebpf-proc",
                        sample_len = item.len(),
                        pid = payload.pid,
                        uid = payload.uid,
                        kind = ?payload.kind,
                        "explicit process ringbuf sample parsed"
                    );
                    if !first_payload_logged {
                        info!(
                            worker = "ebpf-proc",
                            pid = payload.pid,
                            uid = payload.uid,
                            ppid = payload.ppid,
                            kind = ?payload.kind,
                            comm = payload.comm,
                            exe = payload.exe,
                            args = ?payload.args,
                            args_partial = payload.args_partial,
                            ret_code = payload.ret_code,
                            "native eBPF process state event received"
                        );
                        first_payload_logged = true;
                    }
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcStateChanged(payload),
                    );
                    parsed_samples = parsed_samples.saturating_add(1);
                } else {
                    let ev_type =
                        read_ne_value_at(&item, 0, u64::from_ne_bytes).unwrap_or_default();
                    debug!(
                        worker = "ebpf-proc",
                        sample_len = item.len(),
                        ev_type,
                        expected_len = ProcessService::EBPF_EXEC_EVENT_LEN,
                        "explicit process ringbuf sample rejected by parser"
                    );
                    rejected_samples = rejected_samples.saturating_add(1);
                }
            }

            if last_stats_emit.elapsed() >= Duration::from_secs(2) {
                info!(
                    worker = "ebpf-proc",
                    total_samples,
                    parsed_samples,
                    rejected_samples,
                    "explicit process ringbuf sample stats"
                );
                let note = format!(
                    "explicit process ringbuf parse stats parsed={} rejected={}",
                    parsed_samples, rejected_samples
                );
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note,
                    },
                );
                last_stats_emit = Instant::now();
            }

            if samples == 0
                && crate::workers::sleep_with_shutdown(
                    shutdown,
                    Duration::from_millis(100),
                    SHUTDOWN_POLL_INTERVAL,
                )
            {
                break;
            }
        }

        drop(ringbuf);
        drop(bpf);
        Ok(())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn run_proc_explicit_aya_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _proc_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust process eBPF runtime requires aya-ebpf".to_string())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn run_dns_explicit_aya_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _dns_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust DNS eBPF runtime requires aya-ebpf".to_string())
    }

    #[cfg(feature = "aya-ebpf")]
    pub(super) fn run_conn_explicit_aya_runtime(
        shutdown: &CancellationToken,
        conn_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{EbpfLoader, programs::KProbe};

        let mut bpf = EbpfLoader::new().load_file(conn_obj).map_err(|err| {
            format!(
                "load Rust connection object failed ({}): {err}",
                conn_obj.display()
            )
        })?;

        let mut attached = 0usize;
        let mut tunnel_expected = 0usize;
        let mut tunnel_attached = 0usize;
        for spec in Self::conn_kprobe_specs() {
            let is_tunnel = matches!(spec.symbol_name, "udp_tunnel6_xmit_skb" | "iptunnel_xmit");
            if is_tunnel {
                tunnel_expected += 1;
            }

            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                if is_tunnel {
                    warn!(
                        symbol = spec.symbol_name,
                        section = spec.section_name,
                        program = spec.program_name,
                        "connection tunnel probe not found in Aya object"
                    );
                }
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                if is_tunnel {
                    warn!(
                        symbol = spec.symbol_name,
                        "connection tunnel probe handle missing"
                    );
                }
                continue;
            };

            let program: &mut KProbe = match program_handle.try_into() {
                Ok(program) => program,
                Err(_) => {
                    if is_tunnel {
                        warn!(
                            symbol = spec.symbol_name,
                            "connection tunnel probe is not an Aya KProbe"
                        );
                    }
                    continue;
                }
            };

            if let Err(err) = program.load() {
                if is_tunnel {
                    warn!(symbol = spec.symbol_name, detail = %err, "connection tunnel probe load failed");
                }
                continue;
            }

            if program.attach(spec.symbol_name, 0).is_ok() {
                attached += 1;
                if is_tunnel {
                    tunnel_attached += 1;
                }
            } else if is_tunnel {
                warn!(
                    symbol = spec.symbol_name,
                    "connection tunnel probe attach failed"
                );
            }
        }

        info!(
            attached,
            total = Self::conn_kprobe_specs().len(),
            tunnel_attached,
            tunnel_expected,
            "explicit Aya connection kprobe attach summary"
        );

        if tunnel_expected > 0 && tunnel_attached == 0 {
            warn!(
                "no connection tunnel probes were attached; tunnel parity checks may be incomplete on this host"
            );
        }

        if attached == 0 {
            return Err("no Rust connection kprobes attached".to_string());
        }

        let _ = fs::create_dir_all(EbpfPinDomain::Aya.conn_root());
        if !Path::new(EbpfPinDomain::Aya.conn_tcp_map_path()).exists() {
            bpf.map_mut("tcpMap")
                .ok_or_else(|| "Rust connection object map 'tcpMap' not found".to_string())?
                .pin(EbpfPinDomain::Aya.conn_tcp_map_path())
                .map_err(|err| format!("pin Rust connection tcpMap failed: {err}"))?;
        }

        while !shutdown.is_cancelled() {
            if crate::workers::sleep_with_shutdown(
                shutdown,
                Duration::from_millis(250),
                SHUTDOWN_POLL_INTERVAL,
            ) {
                break;
            }
        }

        drop(bpf);
        Ok(())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn run_conn_explicit_aya_runtime(
        _shutdown: &CancellationToken,
        _conn_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust connection eBPF runtime requires aya-ebpf".to_string())
    }
}
