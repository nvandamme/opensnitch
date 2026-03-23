use std::time::Duration;

use crate::platform::adapters::proc_connector::ProcEventSocket;
use crate::platform::adapters::socket_diag::SocketDiagAdapter;
use crate::services::connection::ConnectionService;
use crate::tests::gates::{skip_if_not_opted_in, strict_mode};

#[test]
fn socket_diag_readonly_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let result = SocketDiagAdapter::dump_sockets(0, 0);
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

    let mut socket = match ProcEventSocket::open() {
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

    let _ = ConnectionService::resolve_pid_by_inode(0);
}
