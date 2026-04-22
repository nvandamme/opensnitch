use std::thread;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle as TaskJoinHandle;
use tracing::{error, info, warn};

const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Unknown,
    Running,
    Stopped,
}

impl WorkerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerJoinStatus {
    Stopped,
    Panicked,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCommand {
    Start,
    Stop,
    Probe,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCommandResult {
    Applied,
    Unsupported,
}

pub trait WorkerControl: Send {
    fn worker_name(&self) -> &'static str;

    // Generic command hook; workers can opt in to supported commands.
    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        let _ = command;
        WorkerCommandResult::Unsupported
    }

    // Optional spawn hooks for workers with explicit lifecycle control.
    fn spawn_once(&self) -> WorkerCommandResult {
        self.control(WorkerCommand::Start)
    }

    #[allow(dead_code)]
    fn spawn(&self) -> WorkerCommandResult {
        self.spawn_once()
    }

    // Optional start/stop hooks for workers that support explicit command/control.
    #[allow(dead_code)]
    fn start(&self) {
        let _ = self.spawn();
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
}

struct ThreadWorkerControl {
    name: &'static str,
    handle: ThreadJoinHandle<()>,
}

impl ThreadWorkerControl {
    fn new(name: &'static str, handle: ThreadJoinHandle<()>) -> Self {
        Self { name, handle }
    }
}

pub fn boxed_thread_worker(
    name: &'static str,
    handle: ThreadJoinHandle<()>,
) -> Box<dyn WorkerControl> {
    Box::new(ThreadWorkerControl::new(name, handle))
}

impl WorkerControl for ThreadWorkerControl {
    fn worker_name(&self) -> &'static str {
        self.name
    }

    fn state(&self) -> WorkerState {
        if self.handle.is_finished() {
            WorkerState::Stopped
        } else {
            WorkerState::Running
        }
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        match self.handle.join() {
            Ok(()) => WorkerJoinStatus::Stopped,
            Err(_) => WorkerJoinStatus::Panicked,
        }
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

    pub async fn join_all(self) {
        for task in self.tasks {
            match task.handle.await {
                Ok(()) => info!("task '{}' stopped", task.name),
                Err(err) => error!("task '{}' join error: {}", task.name, err),
            }
        }

        let workers = self.workers;
        match tokio::task::spawn_blocking(move || join_workers(workers)).await {
            Ok(()) => {}
            Err(err) => error!("worker join task failed: {}", err),
        }
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
