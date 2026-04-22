use crate::utils::string_iter::trimmed_non_empty;

#[test]
fn trimmed_non_empty_yields_only_trimmed_non_empty_values() {
    let input = vec!["  one  ", "", "  ", "two", " three"];
    let output: Vec<&str> = trimmed_non_empty(input.iter().copied()).collect();
    assert_eq!(output, vec!["one", "two", "three"]);
}
