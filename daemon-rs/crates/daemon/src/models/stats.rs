#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub total_prompts: u64,
    pub allowed: u64,
    pub denied: u64,
}
