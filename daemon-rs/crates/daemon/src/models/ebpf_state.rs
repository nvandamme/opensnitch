use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BpfMap {
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub max_entries: u32,
}
