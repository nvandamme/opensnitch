#![no_std]
#![cfg_attr(target_arch = "bpf", no_main)]

pub use opensnitch_ebpf_common as common;

pub mod probes {
    #[cfg(target_arch = "bpf")]
    pub mod connection;
    #[cfg(target_arch = "bpf")]
    pub mod dns;
    #[cfg(target_arch = "bpf")]
    pub mod process;
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}