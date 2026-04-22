use std::time::Duration;

use crate::adapters::{proc_connector, socket_diag};
use crate::tests::gates::{skip_if_not_opted_in, strict_mode};
use crate::utils::pid_resolver;

#[test]
fn socket_diag_readonly_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let result = socket_diag::dump_sockets(0, 0);
    if let Err(err) = result
        && strict_mode()
    {
        panic!("socket diag smoke test failed in strict mode: {err}");
    }
}

#[test]
fn proc_connector_readonly_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let socket = match proc_connector::open_proc_events() {
        Ok(socket) => socket,
        Err(err) => {
            if strict_mode() {
                panic!("proc connector open failed in strict mode: {err}");
            }
            return;
        }
    };

    let recv_result = socket.recv_pid_event(Duration::from_millis(25));
    if let Err(err) = recv_result
        && strict_mode()
    {
        panic!("proc connector recv failed in strict mode: {err}");
    }
}

#[test]
fn pid_resolver_non_panicking_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let _ = pid_resolver::resolve_pid_by_inode(0);
}
