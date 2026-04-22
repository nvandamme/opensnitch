use std::fs;

use crate::services::ebpf_runtime_service::ExistingPathCandidatesExt;
use crate::utils::test_support::TestDir;

#[test]
fn find_first_existing_returns_first_match() {
    let dir = TestDir::new("opensnitch-ebpf-runtime-test");
    let first = dir.path.join("missing-1.o");
    let second = dir.path.join("found.o");
    let third = dir.path.join("missing-2.o");
    fs::write(&second, "dummy").expect("write object file");

    let found = [first, second.clone(), third].first_existing();
    assert_eq!(found, Some(second));
}
