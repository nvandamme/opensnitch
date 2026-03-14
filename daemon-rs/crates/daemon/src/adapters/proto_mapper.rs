use std::collections::HashMap;

use crate::models::{
    connection::{ConnectionAttempt, TransportProtocol},
    process::ProcessInfo,
};

pub fn to_proto_connection(
    attempt: &ConnectionAttempt,
    proc_info: &ProcessInfo,
    dst_host: Option<String>,
) -> opensnitch_proto::pb::Connection {
    opensnitch_proto::pb::Connection {
        protocol: match attempt.protocol {
            TransportProtocol::Tcp => "tcp".into(),
            TransportProtocol::Udp => "udp".into(),
        },
        src_ip: attempt.src_ip.clone(),
        src_port: attempt.src_port as u32,
        dst_ip: attempt.dst_ip.clone(),
        dst_host: dst_host.unwrap_or_default(),
        dst_port: attempt.dst_port as u32,

        process_id: attempt.pid as u32,
        user_id: attempt.uid as u32,

        process_path: proc_info.path.clone(),
        process_args: proc_info.args.clone(),
        process_cwd: proc_info.cwd.clone().unwrap_or_default(),
        process_env: HashMap::new(),

        process_checksums: HashMap::new(),
        process_tree: Vec::new(),
    }
}
