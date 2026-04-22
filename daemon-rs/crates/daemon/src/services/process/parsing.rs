use crate::{
    models::{ebpf_payload::EbpfProcStatePayload, proc_event::ProcEventKind},
    utils::byte_read::read_ne_value_at,
    utils::nul_terminated::nul_terminated_utf8_lossy,
};

use super::ProcessService;

impl ProcessService {
    pub(crate) fn parse_ebpf_proc_state_payload(sample: &[u8]) -> Option<EbpfProcStatePayload> {
        if sample.len() < Self::EXEC_HDR_LEN {
            return None;
        }

        let ev_type = read_ne_value_at(sample, 0, u64::from_ne_bytes)?;
        let pid = read_ne_value_at(sample, 8, u32::from_ne_bytes)?;
        let uid = read_ne_value_at(sample, 12, u32::from_ne_bytes)?;
        let ppid = read_ne_value_at(sample, 16, u32::from_ne_bytes)?;
        let ret_code = read_ne_value_at(sample, 20, u32::from_ne_bytes)?;
        let args_count = *sample.get(24)? as usize;
        let args_partial = *sample.get(25)?;

        let mut args = Vec::new();
        let mut filename = String::new();
        let mut comm = String::new();

        if sample.len() >= Self::EBPF_EXEC_EVENT_LEN {
            let filename_off = Self::EXEC_HDR_LEN;
            let args_off = filename_off + Self::MAX_PATH_LEN;
            let comm_off = args_off + (Self::MAX_ARGS * Self::MAX_ARG_LEN);

            filename = nul_terminated_utf8_lossy(
                sample.get(filename_off..filename_off + Self::MAX_PATH_LEN)?,
            );
            comm = nul_terminated_utf8_lossy(sample.get(comm_off..comm_off + Self::TASK_COMM_LEN)?);

            let count = args_count.min(Self::MAX_ARGS);
            for idx in 0..count {
                let start = args_off + (idx * Self::MAX_ARG_LEN);
                let end = start + Self::MAX_ARG_LEN;
                let arg = nul_terminated_utf8_lossy(sample.get(start..end)?);
                if !arg.is_empty() {
                    args.push(arg);
                }
            }
        }

        let kind = match ev_type {
            Self::EV_TYPE_EXEC | Self::EV_TYPE_EXECVEAT => ProcEventKind::Exec,
            Self::EV_TYPE_FORK => ProcEventKind::Fork,
            Self::EV_TYPE_SCHED_EXIT => ProcEventKind::Exit,
            _ => return None,
        };

        Some(EbpfProcStatePayload {
            pid,
            uid,
            ppid,
            kind,
            comm,
            exe: filename,
            args,
            args_partial: args_partial != 0,
            ret_code,
        })
    }
}
