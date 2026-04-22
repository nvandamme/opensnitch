use std::collections::HashMap;

use crate::services::stats::StatsService;

impl StatsService {
    pub(crate) fn probe_bump_limited_counter(
        map: &mut HashMap<String, u64>,
        key: String,
        max_stats: usize,
    ) {
        let mut counters = super::internal::LimitedCountersString {
            map: std::mem::take(map),
            min_key: None,
            min_dirty: true,
        };
        counters.bump(&key, max_stats);
        *map = counters.map;
    }
}
