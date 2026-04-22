fn normalize_hex_token(raw: &str) -> &str {
    raw.trim().trim_start_matches("0x")
}

pub(crate) trait HexToken: Sized {
    fn from_hex_radix(raw: &str) -> Option<Self>;
}

impl HexToken for u8 {
    fn from_hex_radix(raw: &str) -> Option<Self> {
        u8::from_str_radix(raw, 16).ok()
    }
}

impl HexToken for u16 {
    fn from_hex_radix(raw: &str) -> Option<Self> {
        u16::from_str_radix(raw, 16).ok()
    }
}

impl HexToken for u32 {
    fn from_hex_radix(raw: &str) -> Option<Self> {
        u32::from_str_radix(raw, 16).ok()
    }
}

impl HexToken for u64 {
    fn from_hex_radix(raw: &str) -> Option<Self> {
        u64::from_str_radix(raw, 16).ok()
    }
}

pub(crate) fn parse_hex_token<T: HexToken>(raw: &str) -> Option<T> {
    T::from_hex_radix(normalize_hex_token(raw))
}
