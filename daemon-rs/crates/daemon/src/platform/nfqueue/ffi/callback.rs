use std::{ffi::c_void, os::raw::c_int, ptr, sync::atomic::Ordering};

use tracing::warn;

use super::{
    nfgenmsg, nfq_data, nfq_get_gid, nfq_get_indev, nfq_get_msg_packet_hdr, nfq_get_nfmark,
    nfq_get_outdev, nfq_get_payload, nfq_get_uid, nfq_q_handle, nfq_set_verdict2,
};
use crate::platform::nfqueue::metrics::NfqueueMetricsState;
use crate::platform::nfqueue::state::{CapabilitySupport, RUNTIME};
use crate::platform::nfqueue::verdict::NfqueueVerdictEngine;

fn read_uid_gid(nfa: *mut nfq_data) -> (u32, u32) {
    let mut uid = 0_u32;
    let mut gid = 0_u32;

    let Some(runtime) = RUNTIME.get() else {
        unsafe {
            let _ = nfq_get_uid(nfa, &mut uid as *mut u32);
            let _ = nfq_get_gid(nfa, &mut gid as *mut u32);
        }
        return (uid, gid);
    };

    let uid_state = CapabilitySupport::from_u8(runtime.uid_support.load(Ordering::Relaxed));
    if !matches!(uid_state, CapabilitySupport::Unsupported) {
        let rc = unsafe { nfq_get_uid(nfa, &mut uid as *mut u32) };
        if rc >= 0 {
            if matches!(uid_state, CapabilitySupport::Unknown) {
                let _ = runtime.uid_support.compare_exchange(
                    CapabilitySupport::Unknown as u8,
                    CapabilitySupport::Supported as u8,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
        } else if matches!(uid_state, CapabilitySupport::Unknown)
            && runtime
                .uid_support
                .compare_exchange(
                    CapabilitySupport::Unknown as u8,
                    CapabilitySupport::Unsupported as u8,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            warn!("nfqueue uid metadata unavailable; continuing without uid extraction");
        }
    }

    let gid_state = CapabilitySupport::from_u8(runtime.gid_support.load(Ordering::Relaxed));
    if !matches!(gid_state, CapabilitySupport::Unsupported) {
        let rc = unsafe { nfq_get_gid(nfa, &mut gid as *mut u32) };
        if rc >= 0 {
            if matches!(gid_state, CapabilitySupport::Unknown) {
                let _ = runtime.gid_support.compare_exchange(
                    CapabilitySupport::Unknown as u8,
                    CapabilitySupport::Supported as u8,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
        } else if matches!(gid_state, CapabilitySupport::Unknown)
            && runtime
                .gid_support
                .compare_exchange(
                    CapabilitySupport::Unknown as u8,
                    CapabilitySupport::Unsupported as u8,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            warn!("nfqueue gid metadata unavailable; continuing without gid extraction");
        }
    }

    (uid, gid)
}

pub(crate) unsafe extern "C" fn nfqueue_callback(
    qh: *mut nfq_q_handle,
    _nfmsg: *mut nfgenmsg,
    nfa: *mut nfq_data,
    data: *mut c_void,
) -> c_int {
    let queue_num = data as usize as u16;

    let header = unsafe { nfq_get_msg_packet_hdr(nfa) };
    if header.is_null() {
        return 0;
    }

    let packet_id = u32::from_be(unsafe { (*header).packet_id });

    let mut payload_ptr: *mut u8 = ptr::null_mut();
    let payload_len = unsafe { nfq_get_payload(nfa, &mut payload_ptr as *mut *mut u8) };
    let payload = if payload_len > 0 && !payload_ptr.is_null() {
        unsafe { std::slice::from_raw_parts(payload_ptr.cast::<u8>(), payload_len as usize) }
    } else {
        &[]
    };

    let (uid, _) = read_uid_gid(nfa);
    let mark = unsafe { nfq_get_nfmark(nfa) };

    let iface_in_idx = unsafe { nfq_get_indev(nfa) };
    let iface_out_idx = unsafe { nfq_get_outdev(nfa) };

    let packet_verdict = NfqueueVerdictEngine::compute_packet_verdict(
        queue_num,
        packet_id,
        payload,
        uid,
        mark,
        iface_in_idx,
        iface_out_idx,
    );
    NfqueueMetricsState::record_packet_verdict(queue_num, &packet_verdict);

    let (verdict, verdict_mark) = NfqueueVerdictEngine::packet_verdict_to_c(&packet_verdict);
    let (data_len, data_ptr) =
        if let Some(packet) = NfqueueVerdictEngine::packet_verdict_payload(&packet_verdict) {
            (packet.len() as u32, packet.as_ptr())
        } else {
            (0_u32, ptr::null())
        };

    unsafe { nfq_set_verdict2(qh, packet_id, verdict, verdict_mark, data_len, data_ptr) }
}
