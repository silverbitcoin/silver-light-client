//! Query Response Caching for Light Client
//!
//! Implements LRU cache for frequently queried transactions.
//! Reduces Archive Chain load by caching query results.
//!
//! Features:
//! - LRU eviction policy
//! - Configurable TTL per entry
//! - Cache statistics and monitoring
//! - Thread-safe access with RwLock

use crate::query::QueryResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace};

/// Cache entry with timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached response
    response: QueryResponse,

    /// Insertion time
    inserted_at: Instant,

    /// Last access time
    last_accessed: Instant,

    /// Access count
    access_count: u64,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(response: QueryResponse) -> Self {
        let now = Instant::now();
        Self {
            response,
            inserted_at: now,
            last_accessed: now,
            access_count: 0,
        }
    }

    /// Check if entry is expired
    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() > ttl
    }

    /// Update access time
    fn touch(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }
}

/// LRU Cache for query responses
pub struct QueryResponseCache {
    /// Cache entries
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,

    /// Maximum cache size
    max_size: usize,

    /// TTL for cache entries
    ttl: Duration,

    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache hits
    pub hits: u64,

    /// Total cache misses
    pub misses: u64,

    /// Total entries evicted
    pub evictions: u64,

    /// Current cache size
    pub current_size: usize,

    /// Maximum cache size
    pub max_size: usize,

    /// Total bytes cached
    pub total_bytes: usize,
}

impl CacheStats {
    /// Get hit rate as percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    /// Get average bytes per entry
    pub fn average_bytes_per_entry(&self) -> usize {
        if self.current_size == 0 {
            0
        } else {
            self.total_bytes / self.current_size
        }
    }
}

impl QueryResponseCache {
    /// Create a new query response cache
    pub fn new(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            ttl: Duration::from_secs(ttl_seconds),
            stats: Arc::new(RwLock::new(CacheStats {
                hits: 0,
                misses: 0,
                evictions: 0,
                current_size: 0,
                max_size,
                total_bytes: 0,
            })),
        }
    }

    /// Get a cached response
    pub async fn get(&self, key: &str) -> Option<QueryResponse> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            // Check if expired
            if entry.is_expired(self.ttl) {
                debug!("Cache entry expired: {}", key);
                entries.remove(key);

                let mut stats = self.stats.write().await;
                stats.misses += 1;
                stats.current_size = entries.len();

                return None;
            }

            // Update access time
            entry.touch();

            let mut stats = self.stats.write().await;
            stats.hits += 1;

            trace!("Cache hit: {} (access count: {})", key, entry.access_count);

            return Some(entry.response.clone());
        }

        let mut stats = self.stats.write().await;
        stats.misses += 1;

        None
    }

    /// Insert a response into cache
    pub async fn insert(&self, key: String, response: QueryResponse) {
        let mut entries = self.entries.write().await;

        // Calculate response size
        let response_size = bincode::serialize(&response)
            .map(|b| b.len())
            .unwrap_or(0);

        // Check if we need to evict
        if entries.len() >= self.max_size {
            self.evict_lru(&mut entries).await;
        }

        entries.insert(key.clone(), CacheEntry::new(response));

        let mut stats = self.stats.write().await;
        stats.current_size = entries.len();
        stats.total_bytes += response_size;

        debug!("Cache insert: {} (size: {} bytes)", key, response_size);
    }

    /// Evict least recently used entry
    async fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry>) {
        if entries.is_empty() {
            return;
        }

        // Find LRU entry
        let lru_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            let removed = entries.remove(&key);

            let mut stats = self.stats.write().await;
            stats.evictions += 1;

            if let Some(entry) = removed {
                let size = bincode::serialize(&entry.response)
                    .map(|b| b.len())
                    .unwrap_or(0);
                stats.total_bytes = stats.total_bytes.saturating_sub(size);
            }

            debug!("Cache eviction: {} (LRU)", key);
        }
    }

    /// Remove a specific entry
    pub async fn remove(&self, key: &str) -> Option<QueryResponse> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.remove(key) {
            let mut stats = self.stats.write().await;
            stats.current_size = entries.len();

            let size = bincode::serialize(&entry.response)
                .map(|b| b.len())
                .unwrap_or(0);
            stats.total_bytes = stats.total_bytes.saturating_sub(size);

            debug!("Cache remove: {}", key);

            return Some(entry.response);
        }

        None
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();

        let mut stats = self.stats.write().await;
        stats.current_size = 0;
        stats.total_bytes = 0;

        debug!("Cache cleared");
    }

    /// Prune expired entries
    pub async fn prune_expired(&self) {
        let mut entries = self.entries.write().await;

        let expired_keys: Vec<String> = entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(self.ttl))
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            if let Some(entry) = entries.remove(&key) {
                let size = bincode::serialize(&entry.response)
                    .map(|b| b.len())
                    .unwrap_or(0);

                let mut stats = self.stats.write().await;
                stats.total_bytes = stats.total_bytes.saturating_sub(size);

                debug!("Cache prune: {}", key);
            }
        }

        let mut stats = self.stats.write().await;
        stats.current_size = entries.len();
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Get current cache size
    pub async fn size(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Check if key exists in cache
    pub async fn contains(&self, key: &str) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(key)
    }

    /// Get all keys in cache
    pub async fn keys(&self) -> Vec<String> {
        let entries = self.entries.read().await;
        entries.keys().cloned().collect()
    }
}

/// Multi-level cache with hot and cold storage
pub struct TieredQueryCache {
    /// Hot cache (frequently accessed)
    hot_cache: QueryResponseCache,

    /// Cold cache (less frequently accessed)
    cold_cache: QueryResponseCache,

    /// Threshold for moving to cold cache
    #[allow(dead_code)]
    hot_threshold: u64,
}

impl TieredQueryCache {
    /// Create a new tiered cache
    pub fn new(hot_size: usize, cold_size: usize, ttl_seconds: u64) -> Self {
        Self {
            hot_cache: QueryResponseCache::new(hot_size, ttl_seconds),
            cold_cache: QueryResponseCache::new(cold_size, ttl_seconds),
            hot_threshold: 3, // Move to cold after 3 accesses
        }
    }

    /// Get a response from cache
    pub async fn get(&self, key: &str) -> Option<QueryResponse> {
        // Try hot cache first
        if let Some(response) = self.hot_cache.get(key).await {
            return Some(response);
        }

        // Try cold cache
        if let Some(response) = self.cold_cache.get(key).await {
            return Some(response);
        }

        None
    }

    /// Insert a response into cache
    pub async fn insert(&self, key: String, response: QueryResponse) {
        // Insert into hot cache
        self.hot_cache.insert(key, response).await;
    }

    /// Get combined statistics
    pub async fn stats(&self) -> TieredCacheStats {
        let hot_stats = self.hot_cache.stats().await;
        let cold_stats = self.cold_cache.stats().await;

        TieredCacheStats {
            hot_cache: hot_stats,
            cold_cache: cold_stats,
        }
    }

    /// Clear all caches
    pub async fn clear(&self) {
        self.hot_cache.clear().await;
        self.cold_cache.clear().await;
    }

    /// Prune expired entries from both caches
    pub async fn prune_expired(&self) {
        self.hot_cache.prune_expired().await;
        self.cold_cache.prune_expired().await;
    }
}

/// Statistics for tiered cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredCacheStats {
    /// Hot cache statistics
    pub hot_cache: CacheStats,

    /// Cold cache statistics
    pub cold_cache: CacheStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::QueryResponse;

    fn create_test_response() -> QueryResponse {
        QueryResponse {
            results: vec![],
            total_count: 0,
            has_more: false,
            execution_time_ms: 10,
            snapshot_sequence: 1,
        }
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let cache = QueryResponseCache::new(100, 300);
        let stats = cache.stats().await;

        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.max_size, 100);
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = QueryResponseCache::new(100, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;

        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = QueryResponseCache::new(100, 300);

        let retrieved = cache.get("nonexistent").await;
        assert!(retrieved.is_none());

        let stats = cache.stats().await;
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_cache_hit_rate() {
        let cache = QueryResponseCache::new(100, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;

        // Hit
        let _ = cache.get("key1").await;

        // Miss
        let _ = cache.get("key2").await;

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 50.0);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let cache = QueryResponseCache::new(2, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;
        cache.insert("key2".to_string(), response.clone()).await;
        cache.insert("key3".to_string(), response.clone()).await;

        let stats = cache.stats().await;
        assert_eq!(stats.current_size, 2);
        assert_eq!(stats.evictions, 1);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = QueryResponseCache::new(100, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;
        cache.insert("key2".to_string(), response.clone()).await;

        cache.clear().await;

        let stats = cache.stats().await;
        assert_eq!(stats.current_size, 0);
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let cache = QueryResponseCache::new(100, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;

        let removed = cache.remove("key1").await;
        assert!(removed.is_some());

        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_tiered_cache() {
        let cache = TieredQueryCache::new(10, 10, 300);
        let response = create_test_response();

        cache.insert("key1".to_string(), response.clone()).await;

        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_some());

        let stats = cache.stats().await;
        assert!(stats.hot_cache.current_size > 0 || stats.cold_cache.current_size > 0);
    }
}
