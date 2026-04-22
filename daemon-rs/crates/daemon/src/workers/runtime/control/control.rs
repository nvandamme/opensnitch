use std::future::Future;
use std::thread;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle as TaskJoinHandle;
use tracing::{error, info, warn};

pub use crate::models::worker_runtime_control::{
    WorkerCommand, WorkerCommandResult, WorkerJoinStatus, WorkerState,
};

const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn worker_state_from_thread_handle(handle: &ThreadJoinHandle<()>) -> WorkerState {
    if handle.is_finished() {
        WorkerState::Stopped
    } else {
        WorkerState::Running
    }
}

pub(crate) fn worker_join_status_from_thread_result(
    result: thread::Result<()>,
) -> WorkerJoinStatus {
    match result {
        Ok(()) => WorkerJoinStatus::Stopped,
        Err(_) => WorkerJoinStatus::Panicked,
    }
}

pub(crate) fn restartable_worker_state_from_runtime(
    shutdown_cancelled: bool,
    handle: Option<&ThreadJoinHandle<()>>,
) -> WorkerState {
    if shutdown_cancelled {
        WorkerState::Stopped
    } else if handle.is_some_and(|handle| !handle.is_finished()) {
        WorkerState::Running
    } else {
        WorkerState::Stopped
    }
}

pub(crate) fn restartable_worker_is_finished_from_runtime(
    handle: Option<&ThreadJoinHandle<()>>,
) -> bool {
    handle.is_none_or(|handle| handle.is_finished())
}

macro_rules! impl_restartable_thread_worker_control {
    ($worker_ty:ty, $worker_name:expr) => {
        impl $crate::workers::runtime::control::WorkerControl for $worker_ty {
            fn worker_name(&self) -> &'static str {
                $worker_name
            }

            fn control(
                &self,
                command: $crate::workers::runtime::control::WorkerCommand,
            ) -> $crate::workers::runtime::control::WorkerCommandResult {
                match command {
                    $crate::workers::runtime::control::WorkerCommand::Stop => self.stop_worker(),
                    $crate::workers::runtime::control::WorkerCommand::Start => self.start_worker(),
                    $crate::workers::runtime::control::WorkerCommand::Probe => {
                        $crate::workers::runtime::control::WorkerCommandResult::Applied
                    }
                }
            }

            fn state(&self) -> $crate::workers::runtime::control::WorkerState {
                let Ok(runtime) = self.runtime.lock() else {
                    return $crate::workers::runtime::control::WorkerState::Unknown;
                };

                $crate::workers::runtime::control::restartable_worker_state_from_runtime(
                    runtime.shutdown.is_cancelled(),
                    runtime.handle.as_ref(),
                )
            }

            fn is_finished(&self) -> bool {
                let Ok(runtime) = self.runtime.lock() else {
                    return true;
                };

                $crate::workers::runtime::control::restartable_worker_is_finished_from_runtime(
                    runtime.handle.as_ref(),
                )
            }

            fn join(self: Box<Self>) -> $crate::workers::runtime::control::WorkerJoinStatus {
                self.stop();

                let handle = self
                    .runtime
                    .lock()
                    .ok()
                    .and_then(|mut runtime| runtime.handle.take());

                match handle {
                    Some(handle) => {
                        $crate::workers::runtime::control::worker_join_status_from_thread_result(
                            handle.join(),
                        )
                    }
                    None => $crate::workers::runtime::control::WorkerJoinStatus::Stopped,
                }
            }
        }
    };
}

pub(crate) use impl_restartable_thread_worker_control;

pub trait WorkerControl: Send {
    fn worker_name(&self) -> &'static str;

    fn into_worker_control(self) -> Box<dyn WorkerControl>
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }

    // Generic command hook; workers can opt in to supported commands.
    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        let _ = command;
        WorkerCommandResult::Unsupported
    }

    fn stop(&self) {
        let _ = self.control(WorkerCommand::Stop);
    }

    // Optional live-state surface for workers that can expose one.
    fn state(&self) -> WorkerState {
        WorkerState::Unknown
    }

    fn is_finished(&self) -> bool {
        self.state() == WorkerState::Stopped
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus;

    fn spawn_once_thread_with_arg<T>(
        name: &'static str,
        arg: T,
        run_once: fn(T),
    ) -> Box<dyn WorkerControl>
    where
        Self: Sized,
        T: Send + 'static,
    {
        SpawnOnceWorkerControl::spawn_thread(name, move || run_once(arg))
    }

    fn spawn_once_async_thread_with_arg<T, Fut>(
        name: &'static str,
        arg: T,
        run_once: fn(T) -> Fut,
    ) -> Box<dyn WorkerControl>
    where
        Self: Sized,
        T: Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        SpawnOnceWorkerControl::spawn_async_thread(name, arg, run_once)
    }
}

pub struct SpawnOnceWorkerControl {
    name: &'static str,
    handle: ThreadJoinHandle<()>,
}

impl SpawnOnceWorkerControl {
    fn new(name: &'static str, handle: ThreadJoinHandle<()>) -> Self {
        Self { name, handle }
    }

    pub fn spawn_thread(
        name: &'static str,
        run_once: impl FnOnce() + Send + 'static,
    ) -> Box<dyn WorkerControl> {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .spawn(run_once)
            .unwrap_or_else(|err| panic!("failed to spawn one-shot worker '{name}': {err}"));
        Box::new(Self::new(name, handle))
    }

    pub fn spawn_async_thread<T, Fut>(
        name: &'static str,
        arg: T,
        run_once: fn(T) -> Fut,
    ) -> Box<dyn WorkerControl>
    where
        T: Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::spawn_thread(name, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|err| {
                    panic!("failed to build async runtime for one-shot worker '{name}': {err}")
                });
            runtime.block_on(run_once(arg));
        })
    }
}

impl WorkerControl for SpawnOnceWorkerControl {
    fn worker_name(&self) -> &'static str {
        self.name
    }

    fn state(&self) -> WorkerState {
        worker_state_from_thread_handle(&self.handle)
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        worker_join_status_from_thread_result(self.handle.join())
    }
}

pub(crate) struct ThreadWorkerControl {
    name: &'static str,
    handle: ThreadJoinHandle<()>,
}

impl ThreadWorkerControl {
    fn new(name: &'static str, handle: ThreadJoinHandle<()>) -> Self {
        Self { name, handle }
    }

    pub(crate) fn boxed(
        name: &'static str,
        handle: ThreadJoinHandle<()>,
    ) -> Box<dyn WorkerControl> {
        Box::new(Self::new(name, handle))
    }
}

impl WorkerControl for ThreadWorkerControl {
    fn worker_name(&self) -> &'static str {
        self.name
    }

    fn state(&self) -> WorkerState {
        worker_state_from_thread_handle(&self.handle)
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        worker_join_status_from_thread_result(self.handle.join())
    }
}

pub struct RuntimeHandles {
    pub tasks: Vec<NamedTask>,
    pub workers: Vec<Box<dyn WorkerControl>>,
}

pub struct NamedTask {
    pub name: &'static str,
    pub handle: TaskJoinHandle<()>,
}

impl RuntimeHandles {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            workers: Vec::new(),
        }
    }

    pub fn push_task(&mut self, name: &'static str, handle: TaskJoinHandle<()>) {
        self.tasks.push(NamedTask { name, handle });
    }

    pub fn push_worker(&mut self, name: &'static str, handle: ThreadJoinHandle<()>) {
        self.push_worker_control(Box::new(ThreadWorkerControl::new(name, handle)));
    }

    pub fn push_worker_control(&mut self, worker: Box<dyn WorkerControl>) {
        self.workers.push(worker);
    }

    pub fn push_spawn_once_thread_with_arg<T>(
        &mut self,
        name: &'static str,
        arg: T,
        run_once: fn(T),
    ) where
        T: Send + 'static,
    {
        self.push_worker_control(
            <SpawnOnceWorkerControl as WorkerControl>::spawn_once_thread_with_arg(
                name, arg, run_once,
            ),
        );
    }

    pub fn push_spawn_once_async_thread_with_arg<T, Fut>(
        &mut self,
        name: &'static str,
        arg: T,
        run_once: fn(T) -> Fut,
    ) where
        T: Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.push_worker_control(
            <SpawnOnceWorkerControl as WorkerControl>::spawn_once_async_thread_with_arg(
                name, arg, run_once,
            ),
        );
    }

    pub async fn join_all(self) {
        // Await all spawned tasks concurrently so that tasks whose shutdown
        // is already complete don't artificially delay those still running.
        let mut join_set = tokio::task::JoinSet::new();
        for task in self.tasks {
            join_set.spawn(async move {
                let name = task.name;
                match task.handle.await {
                    Ok(()) => info!("task '{}' stopped", name),
                    Err(err) => error!("task '{}' join error: {}", name, err),
                }
            });
        }
        while let Some(result) = join_set.join_next().await {
            if let Err(err) = result {
                error!("task join set error: {err}");
            }
        }

        let workers = self.workers;
        match tokio::task::spawn_blocking(move || Self::join_workers(workers)).await {
            Ok(()) => {}
            Err(err) => error!("worker join task failed: {}", err),
        }
    }

    fn join_workers(workers: Vec<Box<dyn WorkerControl>>) {
        for worker in workers {
            let name = worker.worker_name();
            let started = Instant::now();

            while !worker.is_finished() && started.elapsed() < WORKER_JOIN_TIMEOUT {
                thread::sleep(WORKER_JOIN_POLL_INTERVAL);
            }

            if !worker.is_finished() {
                worker.stop();
                warn!(
                    "worker '{}' state='{}' did not stop within {:?}; detaching thread",
                    name,
                    worker.state().as_str(),
                    WORKER_JOIN_TIMEOUT
                );
                continue;
            }

            match worker.join() {
                WorkerJoinStatus::Stopped => info!("worker '{}' stopped", name),
                WorkerJoinStatus::Panicked => error!("worker '{}' panicked", name),
            }
        }
    }
}
