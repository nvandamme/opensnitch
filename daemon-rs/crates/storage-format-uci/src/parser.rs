use crate::document::{UciDocument, UciEntry, UciSection};
use crate::error::UciParseError;

/// Parse UCI text into a [`UciDocument`].
///
/// Handles `config`, `option`, `list` statements plus `#` comments,
/// blank lines, and `package` lines (skipped for `/etc/config/` compat).
/// Values may be single-quoted, double-quoted, or bare (single word).
pub fn parse(input: &str) -> Result<UciDocument, UciParseError> {
    let mut sections = Vec::new();
    let mut current: Option<UciSection> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        let line_num = idx + 1;

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // `package <name>` — produced by `uci export`, not stored in files.
        // Skip silently for compatibility.
        if line.starts_with("package ") || line == "package" {
            continue;
        }

        if let Some(rest) = line.strip_prefix("config ") {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some(parse_config(rest.trim(), line_num)?);
        } else if line == "config" {
            return Err(UciParseError::MissingSectionType { line: line_num });
        } else if let Some(rest) = line.strip_prefix("option ") {
            let section = current
                .as_mut()
                .ok_or(UciParseError::EntryOutsideSection { line: line_num })?;
            let (name, value) = parse_name_value(rest.trim(), line_num)?;
            section.entries.push(UciEntry::Option { name, value });
        } else if let Some(rest) = line.strip_prefix("list ") {
            let section = current
                .as_mut()
                .ok_or(UciParseError::EntryOutsideSection { line: line_num })?;
            let (name, value) = parse_name_value(rest.trim(), line_num)?;
            section.entries.push(UciEntry::List { name, value });
        } else {
            return Err(UciParseError::UnrecognizedLine { line: line_num });
        }
    }

    if let Some(section) = current {
        sections.push(section);
    }

    Ok(UciDocument { sections })
}

fn parse_config(rest: &str, line_num: usize) -> Result<UciSection, UciParseError> {
    if rest.is_empty() {
        return Err(UciParseError::MissingSectionType { line: line_num });
    }

    let (section_type, remainder) = split_first_word(rest);
    let remainder = remainder.trim();

    let name = if remainder.is_empty() {
        None
    } else {
        Some(parse_value(remainder, line_num)?)
    };

    Ok(UciSection {
        section_type,
        name,
        entries: Vec::new(),
    })
}

fn parse_name_value(rest: &str, line_num: usize) -> Result<(String, String), UciParseError> {
    if rest.is_empty() {
        return Err(UciParseError::MissingOptionName { line: line_num });
    }

    let (name, remainder) = split_first_word(rest);
    let remainder = remainder.trim();

    let value = if remainder.is_empty() {
        String::new()
    } else {
        parse_value(remainder, line_num)?
    };

    Ok((name, value))
}

fn parse_value(input: &str, line_num: usize) -> Result<String, UciParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(String::new());
    }

    match input.as_bytes()[0] {
        b'\'' => {
            let rest = &input[1..];
            match rest.find('\'') {
                Some(end) => Ok(rest[..end].to_string()),
                None => Err(UciParseError::UnterminatedQuote { line: line_num }),
            }
        }
        b'"' => {
            let rest = &input[1..];
            match rest.find('"') {
                Some(end) => Ok(rest[..end].to_string()),
                None => Err(UciParseError::UnterminatedQuote { line: line_num }),
            }
        }
        _ => Ok(input.split_whitespace().next().unwrap_or("").to_string()),
    }
}

fn split_first_word(input: &str) -> (String, &str) {
    match input.find(char::is_whitespace) {
        Some(pos) => (input[..pos].to_string(), &input[pos..]),
        None => (input.to_string(), ""),
    }
}
