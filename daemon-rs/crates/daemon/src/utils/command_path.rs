use crate::utils::path_text::lossy_path;

pub fn resolve_command_path(bin: &str) -> Option<String> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(lossy_path(&candidate));
        }
    }
    None
}
