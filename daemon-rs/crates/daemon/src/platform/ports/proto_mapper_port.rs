//! Port facade for proto mapping.
//!
//! Flows/services should consume this port surface instead of importing
//! `platform::adapters::proto_mapper` directly.

use transport_wire_core::WireConnection;

use crate::models::{connection_state::ConnectionAttempt, process_state::ProcessInfo};
use crate::platform::adapters::proto_mapper::ProtoMapperAdapter;

pub(crate) struct ProtoMapperPort;

impl ProtoMapperPort {
    pub(crate) fn to_wire_connection(
        attempt: &ConnectionAttempt,
        proc_info: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> WireConnection {
        ProtoMapperAdapter::to_wire_connection(attempt, proc_info, dst_host)
    }
}
