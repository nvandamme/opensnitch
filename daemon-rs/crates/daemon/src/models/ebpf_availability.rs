#[derive(Debug, Clone, Copy, Default)]
pub struct EbpfObjectAvailability {
    pub conn_available: bool,
    pub proc_available: bool,
    pub process_available: bool,
    pub dns_available: bool,
}
