use std::time::{Duration, Instant};

use crate::tests::gates::{skip_if_not_opted_in, strict_mode};

#[derive(Clone, Copy)]
struct TimingSummary {
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
}

fn summarize(samples: &[Duration]) -> TimingSummary {
    if samples.is_empty() {
        return TimingSummary {
            mean_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
        };
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let mean_ms =
        samples.iter().map(Duration::as_secs_f64).sum::<f64>() * 1000.0 / samples.len() as f64;

    let p50_idx = ((sorted.len().saturating_sub(1)) as f64 * 0.50).round() as usize;
    let p95_idx = ((sorted.len().saturating_sub(1)) as f64 * 0.95).round() as usize;

    TimingSummary {
        mean_ms,
        p50_ms: sorted[p50_idx].as_secs_f64() * 1000.0,
        p95_ms: sorted[p95_idx].as_secs_f64() * 1000.0,
    }
}

fn print_comparison(label: &str, sync: TimingSummary, async_direct: TimingSummary) {
    println!(
        "{label}: sync mean/p50/p95 = {:.3}/{:.3}/{:.3} ms; async mean/p50/p95 = {:.3}/{:.3}/{:.3} ms",
        sync.mean_ms,
        sync.p50_ms,
        sync.p95_ms,
        async_direct.mean_ms,
        async_direct.p50_ms,
        async_direct.p95_ms,
    );
}

#[test]
fn net_iface_sync_vs_async_harness() {
    if skip_if_not_opted_in() {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime for net iface harness");

    const WARMUP: usize = 3;
    const ITERS: usize = 30;

    for _ in 0..WARMUP {
        let _ = crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_map();
        let _ = rt.block_on(
            crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_map_async(),
        );
    }

    let mut sync_samples = Vec::with_capacity(ITERS);
    let mut async_samples = Vec::with_capacity(ITERS);

    for _ in 0..ITERS {
        let t0 = Instant::now();
        let sync_result = crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_map();
        sync_samples.push(t0.elapsed());

        if let Err(err) = sync_result {
            if strict_mode() {
                panic!("net iface sync harness failed in strict mode: {err}");
            }
            return;
        }

        let t1 = Instant::now();
        let async_result = rt.block_on(
            crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_map_async(),
        );
        async_samples.push(t1.elapsed());

        if let Err(err) = async_result {
            if strict_mode() {
                panic!("net iface async harness failed in strict mode: {err}");
            }
            return;
        }
    }

    let sync_summary = summarize(&sync_samples);
    let async_summary = summarize(&async_samples);
    print_comparison(
        "net_iface (sync-wrapper vs sync-bridge/persistent-rt)",
        sync_summary,
        async_summary,
    );
}

#[test]
fn socket_diag_sync_vs_async_harness() {
    if skip_if_not_opted_in() {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime for socket diag harness");

    let family = nix::libc::AF_INET as u8;
    let protocol = nix::libc::IPPROTO_TCP as u8;

    const WARMUP: usize = 2;
    const ITERS: usize = 20;

    for _ in 0..WARMUP {
        let _ = crate::platform::netstat::socket_diag::SocketDiagAdapter::dump_sockets(
            family, protocol,
        );
        let _ = rt.block_on(
            crate::platform::netstat::socket_diag::SocketDiagAdapter::dump_sockets_async(
                family, protocol,
            ),
        );
        let _ = rt.block_on(
            crate::platform::netstat::socket_diag::SocketDiagAdapter::dump_sockets_async(
                family, protocol,
            ),
        );
    }

    let mut sync_wrapper_samples = Vec::with_capacity(ITERS);
    let mut async_adapter_samples = Vec::with_capacity(ITERS);

    for _ in 0..ITERS {
        let t0 = Instant::now();
        let sync_wrapper_result =
            crate::platform::netstat::socket_diag::SocketDiagAdapter::dump_sockets(
                family, protocol,
            );
        sync_wrapper_samples.push(t0.elapsed());

        if let Err(err) = sync_wrapper_result {
            if strict_mode() {
                panic!("socket diag sync harness failed in strict mode: {err}");
            }
            return;
        }

        let t2 = Instant::now();
        let async_adapter_result = rt.block_on(
            crate::platform::netstat::socket_diag::SocketDiagAdapter::dump_sockets_async(
                family, protocol,
            ),
        );
        async_adapter_samples.push(t2.elapsed());

        if let Err(err) = async_adapter_result {
            if strict_mode() {
                panic!("socket diag adapter-async harness failed in strict mode: {err}");
            }
            return;
        }
    }

    let sync_wrapper_summary = summarize(&sync_wrapper_samples);
    let async_adapter_summary = summarize(&async_adapter_samples);
    print_comparison(
        "socket_diag (sync-wrapper vs async)",
        sync_wrapper_summary,
        async_adapter_summary,
    );
}
