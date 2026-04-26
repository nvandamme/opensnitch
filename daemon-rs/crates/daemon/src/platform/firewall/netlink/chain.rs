use super::NftTable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NftChain {
    table: NftTable,
    name: String,
}

impl NftChain {
    pub(crate) fn new(table: NftTable, name: impl Into<String>) -> Self {
        Self {
            table,
            name: name.into(),
        }
    }

    pub(crate) fn interception_filter_input() -> Self {
        Self::new(NftTable::opensnitch(), "filter_input")
    }

    pub(crate) fn interception_mangle_output() -> Self {
        Self::new(NftTable::opensnitch(), "mangle_output")
    }

    pub(crate) fn family(&self) -> &str {
        self.table.family()
    }

    pub(crate) fn table(&self) -> &NftTable {
        &self.table
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}
