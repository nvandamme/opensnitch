#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StorageEventCounters {
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub scans: u64,
}

impl StorageEventCounters {
    pub(crate) fn saturating_delta(self, previous: Self) -> Self {
        Self {
            reads: self.reads.saturating_sub(previous.reads),
            writes: self.writes.saturating_sub(previous.writes),
            deletes: self.deletes.saturating_sub(previous.deletes),
            scans: self.scans.saturating_sub(previous.scans),
        }
    }

    pub(crate) fn total(self) -> u64 {
        self.reads
            .saturating_add(self.writes)
            .saturating_add(self.deletes)
            .saturating_add(self.scans)
    }
}
