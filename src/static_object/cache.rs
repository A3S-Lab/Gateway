//! Bounded admitted-object cache for WEB0.4.
//!
//! Architecture requires digest/size admission before cache entry creation,
//! namespaced keys (tenant/release/path/encoding), and purge by snapshot
//! replacement (a new `StaticBundleRuntime` owns a fresh cache).

use super::port::StaticObjectBytes;
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Default process-local bound for one static-bundle runtime cache.
pub const DEFAULT_STATIC_OBJECT_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Soft entry cap so tiny objects cannot explode the key map.
pub const DEFAULT_STATIC_OBJECT_CACHE_MAX_ENTRIES: usize = 4_096;

/// Namespaced cache key: tenant namespace + release + manifest + path + encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StaticObjectCacheKey {
    pub object_namespace: String,
    pub release_digest: String,
    pub manifest_digest: String,
    pub path: String,
    pub content_encoding: String,
}

impl StaticObjectCacheKey {
    pub fn new(
        object_namespace: &str,
        release_digest: &str,
        manifest_digest: &str,
        path: &str,
        content_encoding: Option<&str>,
    ) -> Self {
        Self {
            object_namespace: object_namespace.to_owned(),
            release_digest: release_digest.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            path: path.to_owned(),
            content_encoding: content_encoding.unwrap_or("").to_owned(),
        }
    }
}

#[derive(Debug)]
struct CacheEntry {
    body: Bytes,
    digest: String,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<StaticObjectCacheKey, CacheEntry>,
    /// Front is least-recently used.
    order: VecDeque<StaticObjectCacheKey>,
    bytes: u64,
}

/// Process-local LRU of already-admitted static object bytes.
#[derive(Debug)]
pub struct AdmittedObjectCache {
    max_bytes: u64,
    max_entries: usize,
    inner: Mutex<Inner>,
}

impl AdmittedObjectCache {
    pub fn new(max_bytes: u64, max_entries: usize) -> Self {
        Self {
            max_bytes: max_bytes.max(1),
            max_entries: max_entries.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_STATIC_OBJECT_CACHE_MAX_BYTES,
            DEFAULT_STATIC_OBJECT_CACHE_MAX_ENTRIES,
        )
    }

    pub fn get(&self, key: &StaticObjectCacheKey) -> Option<StaticObjectBytes> {
        let mut inner = self.inner.lock().expect("static object cache lock");
        if !inner.map.contains_key(key) {
            return None;
        }
        touch(&mut inner.order, key);
        let entry = inner.map.get(key).expect("checked");
        Some(StaticObjectBytes {
            digest: entry.digest.clone(),
            body: entry.body.clone(),
        })
    }

    /// Insert only after [`super::admit_object_bytes`] has verified size/digest.
    pub fn insert(&self, key: StaticObjectCacheKey, admitted: StaticObjectBytes) {
        let size = admitted.body.len() as u64;
        if size > self.max_bytes {
            return;
        }
        let mut inner = self.inner.lock().expect("static object cache lock");
        if let Some(existing) = inner.map.remove(&key) {
            inner.bytes = inner.bytes.saturating_sub(existing.body.len() as u64);
            remove_key(&mut inner.order, &key);
        }
        while !inner.map.is_empty()
            && (inner.bytes + size > self.max_bytes || inner.map.len() >= self.max_entries)
        {
            let Some(evicted_key) = inner.order.pop_front() else {
                break;
            };
            if let Some(evicted) = inner.map.remove(&evicted_key) {
                inner.bytes = inner.bytes.saturating_sub(evicted.body.len() as u64);
            }
        }
        if inner.bytes + size > self.max_bytes || inner.map.len() >= self.max_entries {
            return;
        }
        inner.bytes += size;
        inner.order.push_back(key.clone());
        inner.map.insert(
            key,
            CacheEntry {
                body: admitted.body,
                digest: admitted.digest,
            },
        );
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("static object cache lock")
            .map
            .len()
    }
}

fn touch(order: &mut VecDeque<StaticObjectCacheKey>, key: &StaticObjectCacheKey) {
    remove_key(order, key);
    order.push_back(key.clone());
}

fn remove_key(order: &mut VecDeque<StaticObjectCacheKey>, key: &StaticObjectCacheKey) {
    if let Some(index) = order.iter().position(|item| item == key) {
        order.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_object::admit_object_bytes;
    use crate::static_object::port::sha256_hex;

    fn admitted(body: &'static [u8]) -> StaticObjectBytes {
        let digest = sha256_hex(body);
        admit_object_bytes(&digest, body.len() as u64, Bytes::from_static(body)).unwrap()
    }

    #[test]
    fn namespaced_keys_do_not_collide_and_lru_evicts() {
        let cache = AdmittedObjectCache::new(20, 2);
        let a = StaticObjectCacheKey::new("tenant-a", "rel", "man", "a.js", None);
        let b = StaticObjectCacheKey::new("tenant-b", "rel", "man", "a.js", None);
        let c = StaticObjectCacheKey::new("tenant-a", "rel", "man", "c.js", None);

        cache.insert(a.clone(), admitted(b"aaaaaaaaaa"));
        cache.insert(b.clone(), admitted(b"bbbbbbbbbb"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&b).is_some());

        // Touch `a`, then insert `c` — `b` is the LRU victim.
        assert!(cache.get(&a).is_some());
        cache.insert(c.clone(), admitted(b"cccccccccc"));
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&c).is_some());
        assert!(cache.get(&b).is_none());
    }

    #[test]
    fn content_encoding_is_part_of_the_cache_key_namespace() {
        let cache = AdmittedObjectCache::new(40, 4);
        let identity = StaticObjectCacheKey::new("ns", "rel", "man", "app.js", None);
        let gzip = StaticObjectCacheKey::new("ns", "rel", "man", "app.js", Some("gzip"));
        cache.insert(identity.clone(), admitted(b"plainplainpl"));
        cache.insert(gzip.clone(), admitted(b"gzipgzipgzip"));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&identity).unwrap().body.as_ref(), b"plainplainpl");
        assert_eq!(cache.get(&gzip).unwrap().body.as_ref(), b"gzipgzipgzip");
    }

    #[test]
    fn rejects_objects_larger_than_the_byte_budget() {
        let cache = AdmittedObjectCache::new(4, 8);
        let key = StaticObjectCacheKey::new("ns", "rel", "man", "big", None);
        cache.insert(key.clone(), admitted(b"too-big"));
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&key).is_none());
    }
}
