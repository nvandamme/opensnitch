// Explicit runtime selection helpers are retained for ebpf-enabled profiles.
#![cfg(any(
    feature = "aya-ebpf",
    feature = "libbpf-ebpf",
    feature = "native-ebpf-ringbuf"
))]

use super::*;

impl EbpfWorkerControl {
    pub(super) fn ensure_ebpf_runtime_loaded(
        _runtime: &mut EbpfService,
        _bus: &Bus,
        mode: EbpfWorkerMode,
    ) {
        // eBPF object loading is handled natively by the aya/libbpf runtimes.
        // bpftool subprocess loading has been removed; it is not available on minimal
        // distros such as Alpine Linux and OpenWrt.
        if (mode.enable_conn || mode.enable_proc) && !Self::ensure_tracefs_ready() {
            warn!(
                "tracefs not ready; eBPF kprobe/tracepoint attach may fail and trigger worker fallback paths"
            );
        }
    }

    pub(super) fn ensure_tracefs_ready() -> bool {
        let tracefs_path = "/sys/kernel/tracing";
        let kprobes_path = "/sys/kernel/tracing/kprobe_events";
        if Path::new(kprobes_path).exists() {
            return true;
        }

        let output = Command::new("mount")
            .args(["-t", "tracefs", "none", tracefs_path])
            .output();

        match output {
            Ok(out) if out.status.success() => Path::new(kprobes_path).exists(),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if !stderr.trim().is_empty() {
                    warn!(detail = %stderr.trim(), "tracefs mount failed");
                }
                Path::new(kprobes_path).exists()
            }
            Err(err) => {
                warn!(detail = %err, "tracefs mount command failed");
                Path::new(kprobes_path).exists()
            }
        }
    }

    pub(super) fn find_libc_path() -> Option<PathBuf> {
        let maps = fs::read_to_string("/proc/self/maps").ok()?;
        Self::find_libc_path_from_maps(&maps)
    }

    pub(super) fn find_libc_path_from_maps(maps: &str) -> Option<PathBuf> {
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            if path.contains("libc.so") {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
            }
        }
        None
    }

    pub(super) fn dns_uprobe_specs() -> &'static [DnsUprobeSpec] {
        &[
            DnsUprobeSpec {
                program_name: "uprobe__gethostbyname",
                section_name: "uprobe/gethostbyname",
                symbol_name: "gethostbyname",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__gethostbyname",
                section_name: "uretprobe/gethostbyname",
                symbol_name: "gethostbyname",
            },
            DnsUprobeSpec {
                program_name: "uprobe__gethostbyname2",
                section_name: "uprobe/gethostbyname2",
                symbol_name: "gethostbyname2",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__gethostbyname2",
                section_name: "uretprobe/gethostbyname2",
                symbol_name: "gethostbyname2",
            },
            DnsUprobeSpec {
                program_name: "uprobe__getaddrinfo",
                section_name: "uprobe/getaddrinfo",
                symbol_name: "getaddrinfo",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__getaddrinfo",
                section_name: "uretprobe/getaddrinfo",
                symbol_name: "getaddrinfo",
            },
        ]
    }

    pub(super) fn proc_tracepoint_specs() -> &'static [ProcTracepointSpec] {
        &[
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_enter_execve",
                section_name: "tracepoint/syscalls/sys_enter_execve",
                category: "syscalls",
                name: "sys_enter_execve",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_enter_execveat",
                section_name: "tracepoint/syscalls/sys_enter_execveat",
                category: "syscalls",
                name: "sys_enter_execveat",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_exit_execve",
                section_name: "tracepoint/syscalls/sys_exit_execve",
                category: "syscalls",
                name: "sys_exit_execve",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_exit_execveat",
                section_name: "tracepoint/syscalls/sys_exit_execveat",
                category: "syscalls",
                name: "sys_exit_execveat",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__sched_sched_process_exit",
                section_name: "tracepoint/sched/sched_process_exit",
                category: "sched",
                name: "sched_process_exit",
            },
        ]
    }

    pub(super) fn select_dns_explicit_runtime(
        runtime: &EbpfService,
    ) -> Option<DnsExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_dns_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.dns_obj.as_deref(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            Self::select_dns_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.dns_obj.as_deref(),
            )
        }
    }

    pub(super) fn select_proc_explicit_runtime(
        runtime: &EbpfService,
    ) -> Option<ProcExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_proc_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = runtime;
            None
        }
    }

    pub(super) fn conn_kprobe_specs() -> &'static [ConnKprobeSpec] {
        &[
            ConnKprobeSpec {
                program_name: "kprobe__tcp_v4_connect",
                section_name: "kprobe/tcp_v4_connect",
                symbol_name: "tcp_v4_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__tcp_v4_connect",
                section_name: "kretprobe/tcp_v4_connect",
                symbol_name: "tcp_v4_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__tcp_v6_connect",
                section_name: "kprobe/tcp_v6_connect",
                symbol_name: "tcp_v6_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__tcp_v6_connect",
                section_name: "kretprobe/tcp_v6_connect",
                symbol_name: "tcp_v6_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udp_sendmsg",
                section_name: "kprobe/udp_sendmsg",
                symbol_name: "udp_sendmsg",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udpv6_sendmsg",
                section_name: "kprobe/udpv6_sendmsg",
                symbol_name: "udpv6_sendmsg",
            },
            ConnKprobeSpec {
                program_name: "kprobe__inet_dgram_connect",
                section_name: "kprobe/inet_dgram_connect",
                symbol_name: "inet_dgram_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__inet_dgram_connect",
                section_name: "kretprobe/inet_dgram_connect",
                symbol_name: "inet_dgram_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udp_tunnel6_xmit_skb",
                section_name: "kprobe/udp_tunnel6_xmit_skb",
                symbol_name: "udp_tunnel6_xmit_skb",
            },
            ConnKprobeSpec {
                program_name: "kprobe__iptunnel_xmit",
                section_name: "kprobe/iptunnel_xmit",
                symbol_name: "iptunnel_xmit",
            },
        ]
    }

    pub(super) fn select_conn_explicit_runtime(
        runtime: &EbpfService,
    ) -> Option<ConnExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_conn_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = runtime;
            None
        }
    }

    #[cfg(feature = "aya-ebpf")]
    pub(super) fn select_conn_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ConnExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya
            && let Some(obj) = rust_ebpf_obj
        {
            return Some(ConnExplicitRuntime {
                kind: ConnExplicitRuntimeKind::Aya,
                obj,
            });
        }

        None
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn select_conn_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        _rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ConnExplicitRuntime<'a>> {
        None
    }

    #[cfg(feature = "aya-ebpf")]
    pub(super) fn select_proc_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ProcExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya
            && let Some(obj) = rust_ebpf_obj
        {
            return Some(ProcExplicitRuntime {
                kind: ProcExplicitRuntimeKind::Aya,
                obj,
            });
        }

        None
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn select_proc_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        _rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ProcExplicitRuntime<'a>> {
        None
    }

    #[cfg(feature = "aya-ebpf")]
    pub(super) fn select_dns_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        legacy_dns_obj: Option<&'a Path>,
        rust_dns_obj: Option<&'a Path>,
    ) -> Option<DnsExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya
            && let Some(obj) = rust_dns_obj
        {
            return Some(DnsExplicitRuntime {
                kind: DnsExplicitRuntimeKind::Aya,
                obj,
            });
        }

        legacy_dns_obj.map(|obj| DnsExplicitRuntime {
            kind: DnsExplicitRuntimeKind::Libbpf,
            obj,
        })
    }

    #[cfg(not(feature = "aya-ebpf"))]
    pub(super) fn select_dns_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        legacy_dns_obj: Option<&'a Path>,
    ) -> Option<DnsExplicitRuntime<'a>> {
        legacy_dns_obj.map(|obj| DnsExplicitRuntime {
            kind: DnsExplicitRuntimeKind::Libbpf,
            obj,
        })
    }

    pub(super) fn run_dns_explicit_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        runtime: DnsExplicitRuntime<'_>,
    ) -> Result<(), String> {
        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            DnsExplicitRuntimeKind::Aya => {
                Self::run_dns_explicit_aya_runtime(bus, shutdown, runtime.obj)
            }
            DnsExplicitRuntimeKind::Libbpf => {
                Self::run_dns_explicit_libbpf_runtime(bus, shutdown, runtime.obj)
            }
        }
    }

    pub(super) fn run_proc_explicit_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        runtime: ProcExplicitRuntime<'_>,
    ) -> Result<(), String> {
        #[cfg(not(feature = "aya-ebpf"))]
        let _ = (bus, shutdown);

        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            ProcExplicitRuntimeKind::Aya => {
                Self::run_proc_explicit_aya_runtime(bus, shutdown, runtime.obj)
            }
        }
    }

    pub(super) fn run_conn_explicit_runtime(
        shutdown: &CancellationToken,
        runtime: ConnExplicitRuntime<'_>,
    ) -> Result<(), String> {
        #[cfg(not(feature = "aya-ebpf"))]
        let _ = shutdown;

        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            ConnExplicitRuntimeKind::Aya => {
                Self::run_conn_explicit_aya_runtime(shutdown, runtime.obj)
            }
        }
    }

    #[cfg(all(feature = "libbpf-ebpf", feature = "native-ebpf-ringbuf"))]
    pub(super) fn run_dns_explicit_libbpf_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        dns_obj: &Path,
    ) -> Result<(), String> {
        use crate::utils::path_text::lossy_os;
        use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, UprobeOpts};
        use std::sync::Arc;

        let libc =
            Self::find_libc_path().ok_or_else(|| "failed to resolve libc path".to_string())?;
        let obj = ObjectBuilder::default()
            .open_file(dns_obj)
            .map_err(|err| format!("open dns object failed ({}): {err}", dns_obj.display()))?
            .load()
            .map_err(|err| format!("load dns object failed ({}): {err}", dns_obj.display()))?;

        let mut attached = 0usize;
        let mut links = Vec::new();
        for prog in obj.progs_mut() {
            let prog_name = lossy_os(prog.name());
            let attach = Self::dns_uprobe_specs()
                .iter()
                .find(|spec| spec.program_name == prog_name)
                .map(|spec| UprobeOpts {
                    retprobe: spec.program_name.starts_with("uretprobe__"),
                    func_name: Some(spec.symbol_name.to_string()),
                    ..Default::default()
                });

            let Some(opts) = attach else {
                continue;
            };
            match prog.attach_uprobe_with_opts(-1, &libc, 0, opts) {
                Ok(link) => {
                    links.push(link);
                    attached += 1;
                }
                Err(err) => {
                    warn!(program = %prog_name, detail = %err, "explicit DNS uprobe attach failed");
                }
            }
        }

        if attached == 0 {
            return Err("no DNS uprobes attached".to_string());
        }

        let map = obj
            .maps()
            .find(|m| m.name() == EVENTS_MAP_NAME)
            .ok_or_else(|| format!("dns object map '{}' not found", EVENTS_MAP_NAME))?;

        let queue = Arc::new(Mutex::new(Vec::<Vec<u8>>::with_capacity(128)));
        let queue_closure = Arc::clone(&queue);
        let mut builder = RingBufferBuilder::new();
        builder
            .add(&map, move |sample: &[u8]| -> i32 {
                if let Ok(mut q) = queue_closure.lock() {
                    q.push(sample.to_vec());
                }
                0
            })
            .map_err(|err| format!("dns ringbuf callback registration failed: {err}"))?;
        let ringbuf = builder
            .build()
            .map_err(|err| format!("dns ringbuf build failed: {err}"))?;

        let mut dns_deduper = DnsEbpfEventDeduper::default();
        while !shutdown.is_cancelled() {
            ringbuf
                .poll(Duration::from_millis(100))
                .map_err(|err| format!("dns ringbuf poll failed: {err}"))?;

            let samples = {
                let mut q = queue
                    .lock()
                    .map_err(|_| "dns ringbuf queue lock poisoned".to_string())?;
                q.drain(..).collect::<Vec<_>>()
            };

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
        drop(links);
        drop(obj);
        Ok(())
    }

    #[cfg(not(all(feature = "libbpf-ebpf", feature = "native-ebpf-ringbuf")))]
    pub(super) fn run_dns_explicit_libbpf_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _dns_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit DNS eBPF runtime requires libbpf-ebpf + native-ebpf-ringbuf".to_string())
    }
}
