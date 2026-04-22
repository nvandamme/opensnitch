/// Unified TOML codec error surface covering decode and encode operations.
#[derive(Debug)]
pub enum TomlCodecError {
    De(toml::de::Error),
    Ser(toml::ser::Error),
}

impl std::fmt::Display for TomlCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::De(err) => err.fmt(f),
            Self::Ser(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for TomlCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::De(err) => Some(err),
            Self::Ser(err) => Some(err),
        }
    }
}
