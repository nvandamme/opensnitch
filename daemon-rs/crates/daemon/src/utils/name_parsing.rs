pub trait ParseFromName: Sized {
    fn parse_from_name(name: &str) -> Self;
}

pub fn normalized_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}
