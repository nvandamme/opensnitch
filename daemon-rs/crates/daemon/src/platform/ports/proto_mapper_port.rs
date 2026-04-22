//! Port facade for proto mapping.
//!
//! Flows/services should consume this port surface instead of importing
//! `platform::adapters::proto_mapper` directly.

use opensnitch_proto::pb;

use crate::models::{
    connection_state::ConnectionAttempt,
    process_state::ProcessInfo,
};
use crate::platform::adapters::proto_mapper::ProtoMapperAdapter;

pub(crate) struct ProtoMapperPort;

impl ProtoMapperPort {
    pub(crate) fn to_proto_process(proc_info: &ProcessInfo) -> pb::Process {
        ProtoMapperAdapter::to_proto_process(proc_info)
    }

    pub(crate) fn to_proto_connection(
        attempt: &ConnectionAttempt,
        proc_info: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> pb::Connection {
        ProtoMapperAdapter::to_proto_connection(attempt, proc_info, dst_host)
    }
}
