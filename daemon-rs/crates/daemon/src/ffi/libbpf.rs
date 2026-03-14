use anyhow::{bail, Result};

pub struct BpfRuntime;

impl BpfRuntime {
    pub fn load_existing_objects() -> Result<Self> {
        bail!("not implemented")
    }
}
