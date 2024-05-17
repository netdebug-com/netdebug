use std::borrow::Borrow;
use std::hash::Hash;

use linked_hash_map::LinkedHashMap;

pub struct EvictingHashMap<'a, K, V> {
    // Fun with callbacks: https://stackoverflow.com/questions/41081240/idiomatic-callbacks-in-rust
    map: LinkedHashMap<K, V>,
    max_elements: usize,
    cb: Box<dyn FnMut(K, V) + Send + 'a>,
}

/// A hash-map with a limited max capacity. Once capacity is reached, adding
/// additional entries to the map will evict the least-recently-used entry.
/// LRU is determined by last *access*.
impl<'a, K, V> EvictingHashMap<'a, K, V>
where
    K: Hash + Eq,
{
    /// Create a new map with maximum size `max_elements`
    /// If an entry is evicted due to max size, `eviction_cb()` will be called with the
    /// evicted key,value pair.
    pub fn new(max_elements: usize, eviction_cb: impl FnMut(K, V) + Send + 'a) -> Self {
        EvictingHashMap {
            map: LinkedHashMap::with_capacity(max_elements),
            max_elements,
            cb: Box::new(eviction_cb),
        }
    }

    /// Returns the keys
    pub fn keys(&self) -> linked_hash_map::Keys<K, V> {
        self.map.keys()
    }

    /// Create an iterator
    pub fn iter(&self) -> linked_hash_map::Iter<K, V> {
        self.map.iter()
    }
    /// Create a mutable iterator
    pub fn iter_mut(&mut self) -> linked_hash_map::IterMut<K, V> {
        self.map.iter_mut()
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        while self.map.len() >= self.max_elements && !self.map.contains_key(&k) {
            // evict oldest entry
            let evicted = self.map.pop_front().unwrap();
            (self.cb)(evicted.0, evicted.1);
        }
        self.map.insert(k, v)
    }

    pub fn front(&self) -> Option<(&K, &V)> {
        self.map.front()
    }

    pub fn pop_front(&mut self) -> Option<(K, V)> {
        self.map.pop_front()
    }

    /// Returns the value corresponding to the key in the map.
    /// If value is found, it is moved to the most-recent position of the LRU
    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get_refresh(k)
    }

    /// Returns the value corresponding to the key in the map.
    pub fn get_mut_no_lru<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get_mut(k)
    }

    /// Returns the value corresponding to the key in the map. *WITHOUT* updating the
    /// LRU.
    pub fn get_no_lru<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get(k)
    }

    pub fn values(&self) -> linked_hash_map::Values<K, V> {
        self.map.values()
    }

    /// Remove the value corresponding to the key. If value was in the map,
    /// it will be returned.
    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.remove(k)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear()
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }
}

#[cfg(test)]
pub mod test {
    use itertools::Itertools;

    use super::*;
    use std::sync::mpsc::{self, TryRecvError};

    fn get_keys(map: &EvictingHashMap<i32, String>) -> Vec<i32> {
        map.keys().cloned().collect()
    }

    fn get_values<'a>(map: &'a EvictingHashMap<i32, String>) -> Vec<&'a str> {
        map.values().map(|s| s.as_str()).collect_vec()
    }

    #[test]
    pub fn test() {
        let (tx, rx) = mpsc::sync_channel(1);
        let cb = |k, v| {
            tx.try_send((k, v)).expect("Failed to write to MSPC queue");
        };
        let mut m = EvictingHashMap::<i32, String>::new(5, cb);

        m.insert(1, "a".to_string());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(m.len(), 1);
        m.insert(2, "b".to_string());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        m.insert(3, "c".to_string());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));

        assert_eq!(get_keys(&m), vec![1, 2, 3]);
        assert_eq!(get_values(&m), vec!["a", "b", "c"]);

        // access element w/o LRU update
        assert_eq!(m.get_no_lru(&1), Some(&"a".to_string()));
        assert_eq!(get_keys(&m), vec![1, 2, 3]);

        // bump access to 1
        assert_eq!(m.get_mut(&1), Some(&mut "a".to_string()));
        assert_eq!(get_keys(&m), vec![2, 3, 1]);

        // values
        assert_eq!(get_values(&m), vec!["b", "c", "a"]);

        m.insert(4, "d".to_string());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        m.insert(5, "e".to_string());
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        // We have reached capacity now.
        assert_eq!(get_keys(&m), vec![2, 3, 1, 4, 5]);

        m.insert(6, "f".to_string());
        assert_eq!(rx.try_recv(), Ok((2, "b".to_string())));
        assert_eq!(get_keys(&m), vec![3, 1, 4, 5, 6]);

        // update a value
        let val = m.get_mut(&4);
        assert!(val.is_some());
        *val.unwrap() = "foo".to_string();
        assert_eq!(m.get_no_lru(&4), Some(&"foo".to_string()));
        assert_eq!(get_keys(&m), vec![3, 1, 5, 6, 4]);

        // update a value without LRU update
        let val = m.get_mut_no_lru(&5);
        assert!(val.is_some());
        *val.unwrap() = "bar".to_string();
        assert_eq!(m.get_no_lru(&5), Some(&"bar".to_string()));
        assert_eq!(get_keys(&m), vec![3, 1, 5, 6, 4]);

        // removal
        assert_eq!(m.remove(&1), Some("a".to_string()));
        assert_eq!(get_keys(&m), vec![3, 5, 6, 4]);

        m.clear();
        assert_eq!(m.len(), 0);
        assert_eq!(get_keys(&m), Vec::<i32>::new())
    }
}
