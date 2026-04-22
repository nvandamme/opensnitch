#![cfg_attr(not(feature = "subscriptions"), allow(dead_code))]

pub(crate) fn sort_by_string_key<T, F>(items: &mut [T], mut key: F)
where
    F: FnMut(&T) -> &str,
{
    items.sort_by(|left, right| key(left).cmp(key(right)));
}