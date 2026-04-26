use std::{ffi::c_void, os::raw::c_int};

#[repr(C)]
pub(crate) struct nfq_handle {
    pub(crate) _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nfq_q_handle {
    pub(crate) _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nfgenmsg {
    pub(crate) _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nfq_data {
    pub(crate) _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct nfqnl_msg_packet_hdr {
    pub(crate) packet_id: u32,
    pub(crate) hw_protocol: u16,
    pub(crate) hook: u8,
}

pub(crate) type NfqCallback =
    unsafe extern "C" fn(*mut nfq_q_handle, *mut nfgenmsg, *mut nfq_data, *mut c_void) -> c_int;

#[link(name = "netfilter_queue")]
unsafe extern "C" {
    pub(crate) fn nfq_open() -> *mut nfq_handle;
    pub(crate) fn nfq_close(h: *mut nfq_handle) -> c_int;
    pub(crate) fn nfq_unbind_pf(h: *mut nfq_handle, pf: u16) -> c_int;
    pub(crate) fn nfq_bind_pf(h: *mut nfq_handle, pf: u16) -> c_int;

    pub(crate) fn nfq_create_queue(
        h: *mut nfq_handle,
        num: u16,
        cb: Option<NfqCallback>,
        data: *mut c_void,
    ) -> *mut nfq_q_handle;
    pub(crate) fn nfq_destroy_queue(qh: *mut nfq_q_handle) -> c_int;

    pub(crate) fn nfq_set_mode(qh: *mut nfq_q_handle, mode: u8, range: u32) -> c_int;
    pub(crate) fn nfq_set_queue_maxlen(qh: *mut nfq_q_handle, queuelen: u32) -> c_int;
    pub(crate) fn nfq_set_queue_flags(qh: *mut nfq_q_handle, mask: u32, flags: u32) -> c_int;
    pub(crate) fn nfq_fd(h: *mut nfq_handle) -> c_int;

    pub(crate) fn nfq_handle_packet(
        h: *mut nfq_handle,
        buf: *mut std::os::raw::c_char,
        len: c_int,
    ) -> c_int;
    pub(crate) fn nfq_get_msg_packet_hdr(tb: *mut nfq_data) -> *mut nfqnl_msg_packet_hdr;
    pub(crate) fn nfq_get_payload(tb: *mut nfq_data, data: *mut *mut u8) -> c_int;
    pub(crate) fn nfq_get_uid(tb: *mut nfq_data, uid: *mut u32) -> c_int;
    pub(crate) fn nfq_get_gid(tb: *mut nfq_data, gid: *mut u32) -> c_int;
    pub(crate) fn nfq_get_indev(tb: *mut nfq_data) -> u32;
    pub(crate) fn nfq_get_outdev(tb: *mut nfq_data) -> u32;
    pub(crate) fn nfq_get_nfmark(tb: *mut nfq_data) -> u32;

    pub(crate) fn nfq_set_verdict2(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        mark: u32,
        datalen: u32,
        buf: *const u8,
    ) -> c_int;
}
