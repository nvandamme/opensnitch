use crate::document::{UciDocument, UciEntry};

/// Emit a [`UciDocument`] as standard UCI text with tab-indented options.
///
/// Output uses single-quoted values and blank-line separation between
/// sections, matching the conventional `/etc/config/*` style.
pub fn emit(doc: &UciDocument) -> String {
    let mut out = String::new();

    for (i, section) in doc.sections.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }

        out.push_str("config ");
        out.push_str(&section.section_type);
        if let Some(ref name) = section.name {
            out.push(' ');
            push_single_quoted(&mut out, name);
        }
        out.push('\n');

        for entry in &section.entries {
            match entry {
                UciEntry::Option { name, value } => {
                    out.push_str("\toption ");
                    out.push_str(name);
                    out.push(' ');
                    push_single_quoted(&mut out, value);
                    out.push('\n');
                }
                UciEntry::List { name, value } => {
                    out.push_str("\tlist ");
                    out.push_str(name);
                    out.push(' ');
                    push_single_quoted(&mut out, value);
                    out.push('\n');
                }
            }
        }
    }

    out
}

fn push_single_quoted(out: &mut String, value: &str) {
    out.push('\'');
    out.push_str(value);
    out.push('\'');
}
