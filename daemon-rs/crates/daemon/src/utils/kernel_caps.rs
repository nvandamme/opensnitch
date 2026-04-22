/// Kernel capability self-check diagnostic — re-exported from `opensnitch-kernel-caps`.
///
/// The implementation lives in `crates/kernel-caps` so that both `daemon` and
/// `tools` can link it directly without subprocess indirection.
pub use opensnitch_kernel_caps::*;
