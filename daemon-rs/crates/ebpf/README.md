# opensnitch-ebpf

This crate is the future kernel-side Rust eBPF home for Aya probe ports from `../../ebpf_prog/`.

Current intent:
- keep kernel-side code in a dedicated crate boundary,
- keep userspace loading/attach/runtime logic in `../daemon`,
- share stable ABI constants and layouts through `../ebpf-common`.

Why this crate is separate from `crates/daemon`:
- eBPF programs target a different architecture/toolchain than userspace,
- verifier constraints and `no_std` requirements differ from daemon runtime code,
- probe rebuild cadence should stay independent from the host daemon binary.

Near-term migration plan:
1. move stable map names and ABI-safe layouts into `opensnitch-ebpf-common`,
2. port one probe family at a time from `ebpf_prog/`,
3. keep libbpf-backed production fallback in place until Aya parity is proven.

Current port status:
- `process` remains placeholder-only,
- `dns` now has an initial Aya probe module mirroring the legacy `gethostbyname` and `getaddrinfo` uprobe/uretprobe flow,
- host-side loading and attach wiring for the Rust DNS object now exists in the daemon DNS-only explicit runtime path.

Build path:
- `make daemon-rs-ebpf-build` invokes `daemon-rs/scripts/build_ebpf.sh`,
- the script expects a nightly Rust toolchain plus the `bpfel-unknown-none` target,
- the script builds the crate as a BPF-only `cdylib` and normalizes the emitted object to `daemon-rs/target/bpfel-unknown-none/{debug,release}/opensnitch-ebpf`, which is now part of daemon-side DNS object discovery.
