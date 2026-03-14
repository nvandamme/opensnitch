use anyhow::{bail, Result};

pub struct NetlinkSocket;

impl NetlinkSocket {
    pub fn open() -> Result<Self> {
        bail!("not implemented")
    }
}
