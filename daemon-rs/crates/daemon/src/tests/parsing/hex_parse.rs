use crate::utils::hex_parse::parse_hex_token;

#[test]
fn parse_hex_u8_token_accepts_prefixed_or_raw_tokens() {
    assert_eq!(parse_hex_token::<u8>("0xff"), Some(255));
    assert_eq!(parse_hex_token::<u8>("ff"), Some(255));
}

#[test]
fn parse_hex_u64_token_accepts_prefixed_or_raw_tokens() {
    assert_eq!(parse_hex_token::<u64>("0x10"), Some(16));
    assert_eq!(parse_hex_token::<u64>("10"), Some(16));
}

#[test]
fn parse_hex_u16_and_u32_tokens_accept_prefixed_or_raw() {
    assert_eq!(parse_hex_token::<u16>("0x01bb"), Some(443));
    assert_eq!(parse_hex_token::<u32>("0100007f"), Some(0x0100_007f));
}

#[test]
fn parse_hex_u8_token_rejects_invalid_data() {
    assert_eq!(parse_hex_token::<u8>("zz"), None);
}

#[test]
fn parse_hex_token_rejects_invalid_data() {
    assert_eq!(parse_hex_token::<u64>("xyz"), None);
}
