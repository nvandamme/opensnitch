use super::EbpfWorkerControl;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn find_libc_path_skips_unmapped_lines() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let temp_path = std::env::temp_dir().join(format!("opensnitchd-libc.so-{unique}"));
    fs::write(&temp_path, b"test").expect("write temp libc path");

    let maps = format!(
        "00400000-00452000 r--p 00000000 00:00 0\n7f1234000000-7f1234100000 r-xp 00000000 08:01 123 {}\n",
        temp_path.display()
    );

    let discovered = EbpfWorkerControl::find_libc_path_from_maps(&maps);
    assert_eq!(discovered, Some(PathBuf::from(&temp_path)));

    let _ = fs::remove_file(temp_path);
}
