/// Generates a thin newtype wrapper around [`control::EbpfWorkerControl`] that
/// is bound to a specific [`control::EbpfWorkerMode`] variant.
///
/// Usage:
/// ```ignore
/// ebpf_worker_newtype!(pub EbpfConnWorkerControl, "ebpf-conn", CONN_ONLY);
/// ```
#[macro_export]
macro_rules! ebpf_worker_newtype {
    ($vis:vis $name:ident, $worker_name:literal, $mode_variant:ident) => {
        $vis struct $name {
            inner: $crate::workers::runtime::ebpf::control::EbpfWorkerControl,
        }

        impl $name {
            $vis fn new(
                bus: $crate::bus::Bus,
                daemon_shutdown: ::tokio_util::sync::CancellationToken,
                tunables: $crate::tunables::RuntimeTunables,
            ) -> Self {
                Self {
                    inner: $crate::workers::runtime::ebpf::control::EbpfWorkerControl::new_with_mode(
                        bus,
                        daemon_shutdown,
                        tunables,
                        $crate::workers::runtime::ebpf::control::EbpfWorkerMode::$mode_variant,
                        $worker_name,
                    ),
                }
            }
        }

        impl $crate::workers::runtime::control::WorkerControl for $name {
            fn worker_name(&self) -> &'static str {
                $worker_name
            }

            fn control(
                &self,
                command: $crate::workers::runtime::control::WorkerCommand,
            ) -> $crate::workers::runtime::control::WorkerCommandResult {
                self.inner.control(command)
            }

            fn state(&self) -> $crate::workers::runtime::control::WorkerState {
                self.inner.state()
            }

            fn is_finished(&self) -> bool {
                self.inner.is_finished()
            }

            fn join(self: Box<Self>) -> $crate::workers::runtime::control::WorkerJoinStatus {
                let Self { inner } = *self;
                Box::new(inner).join()
            }
        }

    };
}
