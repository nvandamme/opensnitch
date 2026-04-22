/// Errors from UCI text parsing.
#[derive(Debug)]
pub enum UciParseError {
    MissingSectionType { line: usize },
    MissingOptionName { line: usize },
    EntryOutsideSection { line: usize },
    UnterminatedQuote { line: usize },
    UnrecognizedLine { line: usize },
}

impl std::fmt::Display for UciParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSectionType { line } => {
                write!(f, "line {line}: missing section type after 'config'")
            }
            Self::MissingOptionName { line } => {
                write!(f, "line {line}: missing option/list name")
            }
            Self::EntryOutsideSection { line } => {
                write!(f, "line {line}: option/list outside of a section")
            }
            Self::UnterminatedQuote { line } => {
                write!(f, "line {line}: unterminated quote")
            }
            Self::UnrecognizedLine { line } => {
                write!(f, "line {line}: unrecognized UCI line")
            }
        }
    }
}

impl std::error::Error for UciParseError {}

/// Unified error surface for the UCI storage-format codec.
#[derive(Debug)]
pub enum UciCodecError {
    Parse(UciParseError),
    SerdeJson(serde_json::Error),
    Structure(String),
}

impl std::fmt::Display for UciCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "UCI parse error: {e}"),
            Self::SerdeJson(e) => write!(f, "serde conversion error: {e}"),
            Self::Structure(msg) => write!(f, "UCI structure error: {msg}"),
        }
    }
}

impl std::error::Error for UciCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::SerdeJson(e) => Some(e),
            Self::Structure(_) => None,
        }
    }
}
