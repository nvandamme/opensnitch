use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct VerdictReply {
    pub request_id: u64,
    pub allow: bool,
    pub reject: bool,
    pub count_stats: bool,
    pub source: &'static str,
    pub rule_name: Option<Arc<str>>,
}
