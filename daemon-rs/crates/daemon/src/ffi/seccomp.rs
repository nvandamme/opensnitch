use anyhow::{bail, Result};

pub struct NotifyFd(pub i32);

pub fn init_seccomp_listener() -> Result<NotifyFd> {
    bail!("not implemented")
}
