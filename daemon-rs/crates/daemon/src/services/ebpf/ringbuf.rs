use std::{path::Path, time::Duration};

use anyhow::Result;

#[cfg(feature = "libbpf-ebpf")]
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(crate) enum EbpfRingbufBackendKind {
    #[cfg(feature = "libbpf-ebpf")]
    Libbpf,
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

pub(crate) struct EbpfRingbufConsumer {
    backend_kind: EbpfRingbufBackendKind,
    inner: BackendInner,
}

impl EbpfRingbufConsumer {
    pub(crate) fn try_open_with_diagnostics(
        map_paths: &[&str],
    ) -> Result<(Self, Vec<String>), String> {
        let mut errors: Vec<String> = Vec::new();

        #[cfg(feature = "aya-ebpf")]
        {
            match AyaRingbuf::try_open(map_paths) {
                Ok(inner) => {
                    return Ok((
                        Self {
                            backend_kind: EbpfRingbufBackendKind::Aya,
                            inner: BackendInner::Aya(inner),
                        },
                        errors,
                    ));
                }
                Err(err) => errors.push(format!("aya backend: {err}")),
            }
        }

        #[cfg(feature = "libbpf-ebpf")]
        {
            match LibbpfRingbuf::try_open(map_paths) {
                Ok(inner) => {
                    return Ok((
                        Self {
                            backend_kind: EbpfRingbufBackendKind::Libbpf,
                            inner: BackendInner::Libbpf(inner),
                        },
                        errors,
                    ));
                }
                Err(err) => errors.push(format!("libbpf backend: {err}")),
            }
        }

        if errors.is_empty() {
            Err("no eBPF ringbuf backend enabled; enable libbpf-ebpf or aya-ebpf".to_string())
        } else {
            Err(errors.join("; "))
        }
    }

    pub(crate) fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        match &mut self.inner {
            #[cfg(feature = "libbpf-ebpf")]
            BackendInner::Libbpf(inner) => inner.poll_samples(timeout),
            #[cfg(feature = "aya-ebpf")]
            BackendInner::Aya(inner) => inner.poll_samples(timeout),
        }
    }

    pub(crate) fn backend_kind(&self) -> &EbpfRingbufBackendKind {
        &self.backend_kind
    }
}

enum BackendInner {
    #[cfg(feature = "libbpf-ebpf")]
    Libbpf(LibbpfRingbuf),
    #[cfg(feature = "aya-ebpf")]
    Aya(AyaRingbuf),
}

#[cfg(feature = "libbpf-ebpf")]
struct LibbpfRingbuf {
    _map: &'static mut libbpf_rs::MapHandle,
    ringbuf: libbpf_rs::RingBuffer<'static>,
    queue: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[cfg(feature = "libbpf-ebpf")]
impl LibbpfRingbuf {
    fn try_open(map_paths: &[&str]) -> Result<Self, String> {
        let map_path = map_paths
            .iter()
            .find(|path| Path::new(path).exists())
            .ok_or_else(|| "no pinned opensnitch ringbuf map found".to_string())?;

        let map = libbpf_rs::MapHandle::from_pinned_path(map_path)
            .map_err(|err| format!("open pinned ringbuf map failed ({map_path}): {err}"))?;
        let map = Box::leak(Box::new(map));

        let queue = Arc::new(Mutex::new(Vec::with_capacity(64)));
        let queue_closure = Arc::clone(&queue);

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(map, move |sample: &[u8]| -> i32 {
                if let Ok(mut q) = queue_closure.lock() {
                    q.push(sample.to_vec());
                }
                0
            })
            .map_err(|err| format!("attach ringbuf callback failed: {err}"))?;

        let ringbuf = builder
            .build()
            .map_err(|err| format!("build ringbuf reader failed: {err}"))?;

        Ok(Self {
            _map: map,
            ringbuf,
            queue,
        })
    }

    fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.ringbuf
            .poll(timeout)
            .map_err(|err| format!("ringbuf poll failed: {err}"))?;

        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "ringbuf queue lock poisoned".to_string())?;

        Ok(queue.drain(..).collect())
    }
}

#[cfg(feature = "aya-ebpf")]
struct AyaRingbuf {
    _map_path: String,
}

#[cfg(feature = "aya-ebpf")]
impl AyaRingbuf {
    fn try_open(map_paths: &[&str]) -> Result<Self, String> {
        let map_path = map_paths
            .iter()
            .find(|path| Path::new(path).exists())
            .ok_or_else(|| "no pinned opensnitch ringbuf map found".to_string())?
            .to_string();

        // Aya backend scaffold only for now. Selection order prefers Aya first,
        // then automatically falls back to libbpf when Aya init is unavailable.
        Err(format!(
            "aya backend scaffold active but ringbuf polling is not implemented yet (map: {map_path})"
        ))
    }

    fn poll_samples(&mut self, _timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        Ok(Vec::new())
    }
}
