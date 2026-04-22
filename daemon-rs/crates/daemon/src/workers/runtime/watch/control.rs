use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio_util::sync::CancellationToken;

use crate::utils::transient_files::is_transient_artifact_name;
use crate::workers::runtime::control::{
    WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus, WorkerState,
};

#[path = "control_trigger.rs"]
mod trigger;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyWatchTargetsBehavior {
    WarnPollFallback,
    #[allow(dead_code)]
    InfoPollFallback,
}

pub(crate) trait WatchWorkerControl: Send + 'static {
    fn worker_name(&self) -> &'static str;
    fn poll_interval(&self) -> Duration;
    fn targets(&self) -> Vec<PathBuf>;
    fn scan<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// Called by the trigger task before `scan()` to indicate whether this
    /// scan was triggered by an inotify event (`true`) or a poll-interval
    /// tick (`false`).  Implementations can use this to skip redundant I/O
    /// when the kernel already told us something changed.
    fn set_inotify_hint(&mut self, _inotify: bool) {}

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
            move |is_inotify| {
                let spec = spec_for_trigger.clone();
                async move {
                    let mut spec = spec.lock().await;
                    spec.set_inotify_hint(is_inotify);
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
    F: FnMut(bool) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut on_scan_trigger = on_scan_trigger;
    trigger::spawn_watch_trigger_task(
        shutdown,
        poll_interval,
        targets,
        empty_targets_behavior,
        move |is_inotify| Box::pin(on_scan_trigger(is_inotify)),
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
