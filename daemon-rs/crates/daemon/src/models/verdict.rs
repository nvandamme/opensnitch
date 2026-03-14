#[derive(Debug, Clone)]
pub struct VerdictReply {
    pub request_id: u64,
    pub allow: bool,
}
