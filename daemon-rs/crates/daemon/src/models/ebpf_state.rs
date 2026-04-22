use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BpfProgram {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub map_ids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BpfMap {
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub max_entries: u32,
}
