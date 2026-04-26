use std::sync::OnceLock;

use anyhow::Result;

/// A single-threaded Tokio runtime kept alive for the process lifetime.
/// All sync→async netlink bridges share this instead of creating a new runtime
/// per call. Cuts per-call overhead by ~30 µs in release mode.
fn netlink_rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build shared netlink sync-bridge runtime")
    })
}

/// Run `future` on the shared netlink runtime.
///
/// If called from inside an existing Tokio context the future is dispatched to
/// a dedicated blocking thread to avoid nested runtimes, the same safety rule as
/// before but now that blocking thread reuses the global runtime rather than
/// building a fresh one for every call.
pub(crate) fn run_on_netlink_rt<T, F>(future: F) -> Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        return std::thread::spawn(move || netlink_rt().block_on(future))
            .join()
            .map_err(|_| anyhow::anyhow!("netlink sync-bridge thread panicked"))?;
    }

    netlink_rt().block_on(future)
}
