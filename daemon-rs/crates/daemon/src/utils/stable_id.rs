use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_pair_u64(first: &str, second: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    first.hash(&mut hasher);
    second.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn hex_id_from_pair(first: &str, second: &str) -> String {
    format!("{:016x}", hash_pair_u64(first, second))
}
