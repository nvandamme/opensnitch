#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NftZone(String);

impl NftZone {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
