use std::{
    sync::{
        Once,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

pub(crate) struct NetlinkRecoveryGate {
    degraded: AtomicBool,
    retry_pending: AtomicBool,
    loop_started: Once,
    domain_name: &'static str,
    retry_delay_ms: AtomicU64,
    poll_interval_ms: AtomicU64,
}

impl NetlinkRecoveryGate {
    pub const fn new(domain_name: &'static str, poll_interval: Duration) -> Self {
        Self {
            degraded: AtomicBool::new(false),
            retry_pending: AtomicBool::new(false),
            loop_started: Once::new(),
            domain_name,
            retry_delay_ms: AtomicU64::new(poll_interval.as_millis() as u64),
            poll_interval_ms: AtomicU64::new(poll_interval.as_millis() as u64),
        }
    }

    pub fn is_available(&self) -> bool {
        !self.degraded.load(Ordering::Relaxed)
    }

    pub fn mark_degraded(&'static self, recovery_probe: fn() -> bool) {
        if !self.degraded.swap(true, Ordering::Relaxed) {
            self.retry_pending.store(true, Ordering::Relaxed);
        }
        self.ensure_recovery_loop_started(recovery_probe);
    }

    pub fn set_retry_delay(&self, retry_delay: Duration) {
        self.retry_delay_ms
            .store(retry_delay.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn set_poll_interval(&self, poll_interval: Duration) {
        self.poll_interval_ms
            .store(poll_interval.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms.load(Ordering::Relaxed)
    }

    pub fn retry_delay_ms(&self) -> u64 {
        self.retry_delay_ms.load(Ordering::Relaxed)
    }

    fn ensure_recovery_loop_started(&'static self, recovery_probe: fn() -> bool) {
        self.loop_started.call_once(|| {
            thread::spawn(move || loop {
                if !self.degraded.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(self.poll_interval_ms()));
                    continue;
                }

                let sleep_ms = if self.retry_pending.swap(false, Ordering::Relaxed) {
                    self.retry_delay_ms()
                } else {
                    self.poll_interval_ms()
                };
                thread::sleep(Duration::from_millis(sleep_ms));

                if recovery_probe() {
                    self.degraded.store(false, Ordering::Relaxed);
                    tracing::info!(
                        domain = self.domain_name,
                        retry_delay_ms = self.retry_delay_ms(),
                        poll_interval_ms = self.poll_interval_ms(),
                        "netlink recovered; resuming primary path"
                    );
                }
            });
        });
    }
}