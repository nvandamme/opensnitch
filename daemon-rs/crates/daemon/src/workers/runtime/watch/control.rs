use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio_util::sync::CancellationToken;

use crate::utils::nul_terminated::nul_terminated_utf8;
use crate::utils::transient_files::is_transient_artifact_name;
use crate::workers::runtime::control::{
    WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus, WorkerState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyWatchTargetsBehavior {
    WarnPollFallback,
    InfoPollFallback,
}

pub(crate) trait WatchWorkerControl: Send + 'static {
    fn worker_name(&self) -> &'static str;
    fn poll_interval(&self) -> Duration;
    fn targets(&self) -> Vec<PathBuf>;
    fn scan<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    fn empty_targets_behavior(&self) -> EmptyWatchTargetsBehavior {
        EmptyWatchTargetsBehavior::WarnPollFallback
    }

    fn path_targets(path: &Path) -> Vec<PathBuf>
    where
        Self: Sized,
    {
        watch_targets(path)
    }

    fn poll_every_secs(secs: u64) -> Duration
    where
        Self: Sized,
    {
        Duration::from_secs(secs)
    }

    fn build(self, shutdown: CancellationToken) -> Box<dyn WorkerControl>
    where
        Self: Sized,
    {
        spawn_watch_worker_control(shutdown, self)
    }
}

pub(crate) fn spawn_watch_worker_control<S>(
    shutdown: CancellationToken,
    spec: S,
) -> Box<dyn WorkerControl>
where
    S: WatchWorkerControl,
{
    let runtime = tokio::runtime::Handle::current();
    let control = GenericWatchWorkerControl::new(runtime, shutdown, spec);
    control.start();
    Box::new(control)
}

struct GenericWatchWorkerControl<S: WatchWorkerControl> {
    runtime: tokio::runtime::Handle,
    parent_shutdown: CancellationToken,
    spec: Arc<tokio::sync::Mutex<S>>,
    name: &'static str,
    poll_interval: Duration,
    targets: Vec<PathBuf>,
    empty_targets_behavior: EmptyWatchTargetsBehavior,
    token: Mutex<Option<CancellationToken>>,
    trigger_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<S: WatchWorkerControl> GenericWatchWorkerControl<S> {
    fn new(runtime: tokio::runtime::Handle, parent_shutdown: CancellationToken, spec: S) -> Self {
        let name = spec.worker_name();
        let poll_interval = spec.poll_interval();
        let targets = spec.targets();
        let empty_targets_behavior = spec.empty_targets_behavior();
        Self {
            runtime,
            parent_shutdown,
            spec: Arc::new(tokio::sync::Mutex::new(spec)),
            name,
            poll_interval,
            targets,
            empty_targets_behavior,
            token: Mutex::new(None),
            trigger_handle: Mutex::new(None),
        }
    }

    fn start(&self) {
        let trigger_running = self
            .trigger_handle
            .lock()
            .expect("watch trigger handle mutex poisoned")
            .as_ref()
            .is_some_and(|h| !h.is_finished());
        if trigger_running {
            return;
        }

        let run_token = self.parent_shutdown.child_token();
        {
            let mut token_guard = self
                .token
                .lock()
                .expect("watch worker token mutex poisoned");
            *token_guard = Some(run_token.clone());
        }

        // Run an initial scan immediately on startup (matches the previous
        // scan_task's initial scan_tx.try_send()).
        let spec_init = self.spec.clone();
        let init_token = run_token.clone();
        tokio::spawn(async move {
            if !init_token.is_cancelled() {
                let mut spec = spec_init.lock().await;
                spec.scan().await;
            }
        });

        // The trigger task calls spec.scan() directly — matching Go's pattern
        // where the goroutine receiving the fsnotify event immediately executes
        // the handler inline.  Previous design routed through an intermediate
        // scan_tx channel and a separate scan_task (two async hops).
        // Coalescing is preserved: the trigger loop calls the callback once per
        // should_scan=true iteration; rapid inotify events accumulate in the
        // inotify channel while scan() runs and are all observed next iteration.
        let spec_for_trigger = self.spec.clone();
        let trigger_task = spawn_scanner_watch_task(
            run_token,
            self.poll_interval,
            self.targets.clone(),
            self.empty_targets_behavior,
            move || {
                let spec = spec_for_trigger.clone();
                async move {
                    let mut spec = spec.lock().await;
                    spec.scan().await;
                }
            },
        );
        *self
            .trigger_handle
            .lock()
            .expect("watch trigger handle mutex poisoned") = Some(trigger_task);
    }

    fn stop(&self) {
        if let Some(token) = self
            .token
            .lock()
            .expect("watch worker token mutex poisoned")
            .as_ref()
            .cloned()
        {
            token.cancel();
        }
    }
}

pub(crate) fn spawn_scanner_watch_task<F, Fut>(
    shutdown: CancellationToken,
    poll_interval: Duration,
    targets: Vec<PathBuf>,
    empty_targets_behavior: EmptyWatchTargetsBehavior,
    on_scan_trigger: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut on_scan_trigger = on_scan_trigger;
    spawn_watch_trigger_task(
        shutdown,
        poll_interval,
        targets,
        empty_targets_behavior,
        move || {
        Box::pin(on_scan_trigger())
        },
    )
}

pub(crate) fn should_forward_inotify_mask(mask: u32) -> bool {
    let watched = nix::libc::IN_CREATE
        | nix::libc::IN_MODIFY
        | nix::libc::IN_DELETE
        | nix::libc::IN_MOVED_FROM
        | nix::libc::IN_MOVED_TO
        | nix::libc::IN_CLOSE_WRITE
        | nix::libc::IN_DELETE_SELF
        | nix::libc::IN_MOVE_SELF;

    (mask & watched) != 0
}

pub(crate) fn is_transient_watch_event_name(name: &str) -> bool {
    is_transient_artifact_name(name)
}

pub(crate) fn watch_targets(path: &Path) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if path.exists() {
        targets.push(path.to_path_buf());
    }
    if let Some(parent) = path.parent() {
        targets.push(parent.to_path_buf());
    }
    targets.sort();
    targets.dedup();
    targets
}

pub(crate) fn is_newer_mtime(current: Option<SystemTime>, previous: Option<SystemTime>) -> bool {
    matches!((previous, current), (Some(prev), Some(cur)) if cur > prev)
}

fn spawn_watch_trigger_task<F>(
    shutdown: CancellationToken,
    poll_interval: Duration,
    targets: Vec<PathBuf>,
    empty_targets_behavior: EmptyWatchTargetsBehavior,
    mut on_scan_trigger: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    tokio::spawn(async move {
        let (_watcher, mut fs_rx_enabled, mut fs_rx) =
            setup_fs_trigger(&targets, empty_targets_behavior);

        loop {
            let mut should_scan = false;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(poll_interval) => {
                    should_scan = true;
                }
                event = fs_rx.recv(), if fs_rx_enabled => {
                    match event {
                        Some(()) => should_scan = true,
                        None => {
                            fs_rx_enabled = false;
                            tracing::warn!(interval = ?poll_interval, "filesystem watch channel closed, continuing with poll-only fallback");
                        }
                    }
                }
            }

            if !should_scan {
                continue;
            }

            on_scan_trigger().await;
        }
    })
}

fn setup_fs_trigger(
    paths: &[PathBuf],
    empty_targets_behavior: EmptyWatchTargetsBehavior,
) -> (
    Option<InotifyTrigger>,
    bool,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let fd = {
        let flags = nix::libc::IN_NONBLOCK | nix::libc::IN_CLOEXEC;
        // SAFETY: Calling libc syscall with constant flags and checking return value.
        let created = unsafe { nix::libc::inotify_init1(flags) };
        if created < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("failed to initialize inotify, using poll-only fallback: {err}");
            return (None, false, rx);
        }
        created
    };

    let mut watched_any = false;
    let mask = nix::libc::IN_CREATE
        | nix::libc::IN_MODIFY
        | nix::libc::IN_DELETE
        | nix::libc::IN_MOVED_FROM
        | nix::libc::IN_MOVED_TO
        | nix::libc::IN_CLOSE_WRITE
        | nix::libc::IN_DELETE_SELF
        | nix::libc::IN_MOVE_SELF;

    for path in paths {
        let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(path = %path.display(), "failed to watch path with interior NUL, keeping poll fallback");
                continue;
            }
        };

        // SAFETY: fd is valid from inotify_init1; c_path is a valid C string.
        let watch_rc = unsafe { nix::libc::inotify_add_watch(fd, c_path.as_ptr(), mask) };
        if watch_rc >= 0 {
            watched_any = true;
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(path = %path.display(), "failed to watch filesystem path, keeping poll fallback: {err}");
        }
    }

    if !watched_any {
        // SAFETY: fd was created by inotify_init1 and is no longer needed.
        unsafe {
            nix::libc::close(fd);
        }
        match empty_targets_behavior {
            EmptyWatchTargetsBehavior::WarnPollFallback => {
                tracing::warn!("no filesystem watch targets registered, using poll-only fallback");
            }
            EmptyWatchTargetsBehavior::InfoPollFallback => {
                tracing::info!("no filesystem watch targets registered by design, using poll-only fallback");
            }
        }
        return (None, false, rx);
    }

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let worker = std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];

        // Use epoll to wait for inotify events with near-zero latency instead of sleeping.
        // SAFETY: epoll_create1 with EPOLL_CLOEXEC; return value checked below.
        let epoll_fd = unsafe { nix::libc::epoll_create1(nix::libc::EPOLL_CLOEXEC) };
        let use_epoll = if epoll_fd >= 0 {
            let mut ev = nix::libc::epoll_event {
                events: nix::libc::EPOLLIN as u32,
                u64: 0,
            };
            // SAFETY: epoll_fd and fd are both valid; ev is properly initialised.
            let rc = unsafe { nix::libc::epoll_ctl(epoll_fd, nix::libc::EPOLL_CTL_ADD, fd, &mut ev) };
            rc >= 0
        } else {
            false
        };

        while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
            if use_epoll {
                // Block until the inotify fd is readable or the 10 ms timeout expires so
                // we can re-check the stop flag without busy-spinning.
                let mut events = [nix::libc::epoll_event { events: 0, u64: 0 }; 1];
                // SAFETY: epoll_fd is valid; events slice is writable and correctly sized.
                let n = unsafe {
                    nix::libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 1, 10)
                };
                if n <= 0 {
                    continue;
                }
            }

            // SAFETY: fd is a live inotify descriptor; buffer is writable and sized correctly.
            let bytes_read = unsafe {
                nix::libc::read(
                    fd,
                    buffer.as_mut_ptr().cast::<nix::libc::c_void>(),
                    buffer.len(),
                )
            };

            if bytes_read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    tracing::warn!("inotify read failed, keeping poll fallback active: {err}");
                    break;
                }
                if !use_epoll {
                    std::thread::sleep(Duration::from_millis(10));
                }
                continue;
            }

            if bytes_read == 0 {
                if !use_epoll {
                    std::thread::sleep(Duration::from_millis(10));
                }
                continue;
            }

            let mut offset = 0_usize;
            let mut emit = false;
            let header_size = std::mem::size_of::<nix::libc::inotify_event>();
            while offset + header_size <= bytes_read as usize {
                // SAFETY: offset bounds are checked above for inotify_event header size.
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer[offset..].as_ptr().cast::<nix::libc::inotify_event>(),
                    )
                };
                let name = if event.len > 0 {
                    let name_start = offset + header_size;
                    let name_end = name_start.saturating_add(event.len as usize);
                    if name_end <= bytes_read as usize {
                        let raw_name = &buffer[name_start..name_end];
                        nul_terminated_utf8(raw_name)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let is_transient = name.is_some_and(is_transient_watch_event_name);
                if should_forward_inotify_mask(event.mask) && !is_transient {
                    emit = true;
                }

                let event_size = header_size + event.len as usize;
                if event_size == 0 {
                    break;
                }
                offset = offset.saturating_add(event_size);
            }

            if emit {
                let _ = tx.send(());
            }
        }

        // SAFETY: epoll_fd was created in this function and should be closed once worker exits.
        if use_epoll {
            unsafe { nix::libc::close(epoll_fd) };
        }
        // SAFETY: fd was created in this function and should be closed once worker exits.
        unsafe {
            nix::libc::close(fd);
        }
    });

    (
        Some(InotifyTrigger {
            stop,
            worker: Some(worker),
        }),
        true,
        rx,
    )
}

struct InotifyTrigger {
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InotifyTrigger {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl<S: WatchWorkerControl> WorkerControl for GenericWatchWorkerControl<S> {
    fn worker_name(&self) -> &'static str {
        self.name
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Start => {
                self.start();
                WorkerCommandResult::Applied
            }
            WorkerCommand::Stop => {
                self.stop();
                WorkerCommandResult::Applied
            }
            WorkerCommand::Probe => WorkerCommandResult::Applied,
        }
    }

    fn state(&self) -> WorkerState {
        let trigger_running = self
            .trigger_handle
            .lock()
            .expect("watch trigger handle mutex poisoned")
            .as_ref()
            .is_some_and(|h| !h.is_finished());
        if trigger_running {
            WorkerState::Running
        } else {
            WorkerState::Stopped
        }
    }

    fn is_finished(&self) -> bool {
        self.state() == WorkerState::Stopped
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.stop();
        let trigger = self
            .trigger_handle
            .lock()
            .expect("watch trigger handle mutex poisoned")
            .take();

        let mut panicked = false;
        if let Some(handle) = trigger {
            match self.runtime.block_on(async { handle.await }) {
                Ok(()) => {}
                Err(err) if err.is_panic() => panicked = true,
                Err(_) => {}
            }
        }

        if panicked {
            WorkerJoinStatus::Panicked
        } else {
            WorkerJoinStatus::Stopped
        }
    }
}
