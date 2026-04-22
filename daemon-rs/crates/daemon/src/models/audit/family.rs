/// Cross-cutting event family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventFamily {
    HotPath,
    ColdPath,
}

impl std::fmt::Display for AuditEventFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HotPath => f.write_str("hot"),
            Self::ColdPath => f.write_str("cold"),
        }
    }
}
