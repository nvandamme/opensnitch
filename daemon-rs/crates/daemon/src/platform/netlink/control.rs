use anyhow::Result;
use nix::libc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetlinkControlFlow {
    Process,
    Ignore,
}

pub(crate) fn classify_nlmsg_control(msg_type: u16, payload: &[u8]) -> Result<NetlinkControlFlow> {
    if msg_type == libc::NLMSG_NOOP as u16 || msg_type == libc::NLMSG_DONE as u16 {
        return Ok(NetlinkControlFlow::Ignore);
    }

    if msg_type == libc::NLMSG_ERROR as u16 {
        if payload.len() < 4 {
            return Ok(NetlinkControlFlow::Ignore);
        }
        let code = i32::from_ne_bytes(payload[0..4].try_into()?);
        if code != 0 {
            let err = std::io::Error::from_raw_os_error((-code).max(1));
            return Err(err.into());
        }
        return Ok(NetlinkControlFlow::Ignore);
    }

    Ok(NetlinkControlFlow::Process)
}
