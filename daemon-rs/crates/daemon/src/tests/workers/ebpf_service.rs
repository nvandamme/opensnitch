use std::fs;

use crate::services::ebpf::EbpfService;
use crate::tests::support::TestDir;

#[test]
fn find_first_existing_returns_first_match() {
    let dir = TestDir::new("opensnitch-ebpf-runtime-test");
    let first = dir.path.join("missing-1.o");
    let second = dir.path.join("found.o");
    let third = dir.path.join("missing-2.o");
    fs::write(&second, "dummy").expect("write object file");

    let found = EbpfService::probe_first_existing_path(&[first, second.clone(), third]);
    assert_eq!(found, Some(second));
}
