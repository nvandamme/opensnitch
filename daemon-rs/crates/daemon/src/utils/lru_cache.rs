use std::{borrow::Borrow, hash::Hash, num::NonZeroUsize};

pub(crate) struct LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    entries: lru::LruCache<K, V>,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("non-zero capacity");
        Self {
            entries: lru::LruCache::new(cap),
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        self.entries.put(key, value);
    }

    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("non-zero capacity");
        self.entries.resize(cap);
    }

    pub(crate) fn remove_by<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.pop(key)
    }

    pub(crate) fn get_cloned_by<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
        V: Clone,
    {
        self.entries.get(key).cloned()
    }

    pub(crate) fn peek_cloned_by<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
        V: Clone,
    {
        self.entries.peek(key).cloned()
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::LruCache;

    #[test]
    fn evicts_least_recently_used_entry() {
        let mut cache = LruCache::new(2);
        cache.insert("a".to_string(), 1_u32);
        cache.insert("b".to_string(), 2_u32);

        // Touch "a" so "b" becomes the next eviction candidate.
        assert_eq!(cache.get_cloned_by("a"), Some(1));

        cache.insert("c".to_string(), 3_u32);

        assert_eq!(cache.get_cloned_by("a"), Some(1));
        assert_eq!(cache.get_cloned_by("b"), None);
        assert_eq!(cache.get_cloned_by("c"), Some(3));
    }
}
