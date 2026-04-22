pub(crate) fn is_transient_artifact_name(name: &str) -> bool {
    !name.is_empty()
        && (name.starts_with('.')
            || name.ends_with(".tmp")
            || name.ends_with(".download")
            || name.contains(".tmp-"))
}
