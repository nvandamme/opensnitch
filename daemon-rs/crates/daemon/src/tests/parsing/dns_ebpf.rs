use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use opensnitch_ebpf_common::dns::{AF_INET, AF_INET6, DnsEvent, HOST_LEN, IP_LEN};

use crate::{models::dns_payload::DnsPayload, services::dns::DnsService};

fn build_dns_sample(addr_type: u32, ip: [u8; IP_LEN], host: &str) -> [u8; DnsEvent::LEN] {
    let mut sample = [0_u8; DnsEvent::LEN];
    sample[..4].copy_from_slice(&addr_type.to_ne_bytes());
    sample[4..20].copy_from_slice(&ip);

    let host_bytes = host.as_bytes();
    let copy_len = host_bytes.len().min(HOST_LEN.saturating_sub(1));
    sample[20..20 + copy_len].copy_from_slice(&host_bytes[..copy_len]);

    sample
}

#[test]
fn dns_event_wire_len_matches_parser_expectation() {
    assert_eq!(DnsEvent::LEN, DnsService::EBPF_DNS_EVENT_LEN);
}

#[test]
fn parse_ebpf_dns_sample_reads_ipv4_answer() {
    let mut ip = [0_u8; IP_LEN];
    ip[..4].copy_from_slice(&[1, 1, 1, 1]);
    let sample = build_dns_sample(AF_INET, ip, "Example.COM.");

    let payload = DnsService::parse_ebpf_dns_sample(&sample);

    assert_eq!(
        payload,
        Some(DnsPayload::answer(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ))
    );
}

#[test]
fn parse_ebpf_dns_sample_reads_ipv6_answer() {
    let ip = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let sample = build_dns_sample(AF_INET6, ip, "ipv6.example");

    let payload = DnsService::parse_ebpf_dns_sample(&sample);

    assert_eq!(
        payload,
        Some(DnsPayload::answer(
            "ipv6.example",
            IpAddr::V6(Ipv6Addr::from(ip)),
        ))
    );
}

#[test]
fn parse_ebpf_dns_sample_rejects_unknown_family() {
    let sample = build_dns_sample(0, [0; IP_LEN], "example.com");

    assert_eq!(DnsService::parse_ebpf_dns_sample(&sample), None);
}