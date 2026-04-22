pub(crate) fn trimmed_non_empty<'a, I>(iter: I) -> impl Iterator<Item = &'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    iter.into_iter()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
