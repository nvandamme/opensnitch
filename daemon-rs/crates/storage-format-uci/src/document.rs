/// A parsed UCI configuration file (one `/etc/config/<package>` file).
///
/// Sections are stored in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciDocument {
    pub sections: Vec<UciSection>,
}

/// A section within a UCI config file.
///
/// ```text
/// config <section_type> ['<name>']
///     option <key> '<value>'
///     list <key> '<value>'
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciSection {
    /// Section type (e.g. `"interface"`, `"rule"`, `"daemon"`).
    pub section_type: String,
    /// Section name, if named. `None` for anonymous sections.
    pub name: Option<String>,
    /// Options and list entries in declaration order.
    pub entries: Vec<UciEntry>,
}

/// A single `option` or `list` line within a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UciEntry {
    /// `option <name> '<value>'`
    Option { name: String, value: String },
    /// `list <name> '<value>'` (one line; multiple lines with the same name
    /// form a list when collected).
    List { name: String, value: String },
}
