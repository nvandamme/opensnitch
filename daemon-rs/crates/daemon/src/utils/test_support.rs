#[cfg(test)]
use std::{fs, path::PathBuf, sync::Once};

#[cfg(test)]
use crate::utils::time_nonce::unique_name;

#[cfg(test)]
pub(crate) struct TestDir {
    pub(crate) path: PathBuf,
}

#[cfg(test)]
impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name(prefix));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
pub(crate) fn init_test_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        crate::logging::init_for_tests();
    });
}
