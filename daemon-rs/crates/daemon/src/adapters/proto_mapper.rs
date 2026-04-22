use std::collections::HashMap;

use crate::models::{
    connection_state::{ConnectionAttempt, TransportProtocol},
    process_state::ProcessInfo,
};

pub fn to_proto_connection(
    attempt: &ConnectionAttempt,
    proc_info: &ProcessInfo,
    dst_host: Option<String>,
) -> opensnitch_proto::pb::Connection {
    let process_env = proc_info
        .env_preview
        .iter()
        .filter_map(|entry| {
            let (k, v) = entry.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect::<HashMap<_, _>>();

    let mut process_checksums = HashMap::new();
    if let Some(hash) = proc_info
        .process_hash_md5
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        process_checksums.insert("md5".to_string(), hash.clone());
    }
    if let Some(hash) = proc_info
        .process_hash_sha1
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        process_checksums.insert("sha1".to_string(), hash.clone());
    }
    if let Some(hash) = proc_info
        .process_hash
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        process_checksums.insert("sha256".to_string(), hash.clone());
    }

    let process_tree = proc_info
        .parent_chain
        .iter()
        .map(|node| opensnitch_proto::pb::StringInt {
            key: node.path.clone(),
            value: node.pid,
        })
        .collect::<Vec<_>>();

    opensnitch_proto::pb::Connection {
        protocol: match attempt.protocol {
            TransportProtocol::Tcp => "tcp".into(),
            TransportProtocol::Udp => "udp".into(),
            TransportProtocol::UdpLite => "udplite".into(),
            TransportProtocol::Sctp => "sctp".into(),
            TransportProtocol::Icmp => "icmp".into(),
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
        process_env,
        process_checksums,
        process_tree,
    }
}
