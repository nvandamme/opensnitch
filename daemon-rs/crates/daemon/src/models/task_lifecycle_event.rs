#[derive(Debug, Clone)]
pub enum TaskLifecycleEvent {
    Added { task_name: String, task_key: String },
    Removed { task_name: String, task_key: String },
    PausedAll { task_count: usize },
    ResumedAll { task_count: usize },
}
