use std::thread::JoinHandle as ThreadJoinHandle;

use tokio::task::JoinHandle as TaskJoinHandle;
use tracing::{error, info};

pub struct RuntimeHandles {
    pub tasks: Vec<NamedTask>,
    pub workers: Vec<NamedWorker>,
}

pub struct NamedTask {
    pub name: &'static str,
    pub handle: TaskJoinHandle<()>,
}

pub struct NamedWorker {
    pub name: &'static str,
    pub handle: ThreadJoinHandle<()>,
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
        self.workers.push(NamedWorker { name, handle });
    }

    pub async fn join_all(self) {
        for task in self.tasks {
            match task.handle.await {
                Ok(()) => info!("task '{}' stopped", task.name),
                Err(err) => error!("task '{}' join error: {}", task.name, err),
            }
        }

        for worker in self.workers {
            match worker.handle.join() {
                Ok(()) => info!("worker '{}' stopped", worker.name),
                Err(_) => error!("worker '{}' panicked", worker.name),
            }
        }
    }
}
