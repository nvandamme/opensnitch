use crate::models::proc_event::ProcEventKind;

#[derive(Debug, Clone)]
pub struct EbpfProcStatePayload {
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub kind: ProcEventKind,
    pub comm: String,
    pub exe: String,
    pub args: Vec<String>,
    pub args_partial: bool,
    pub ret_code: u32,
}
