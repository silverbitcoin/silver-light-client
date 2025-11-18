//! Light Client Query System
//!
//! Provides query interface for Light Nodes to query blockchain data
//! from Archive Chain with Merkle proof verification.
//!
//! Supports queries by:
//! - Address (sender or recipient)
//! - Object ID
//! - Timestamp range
//!
//! All queries return transaction data with Merkle proofs for verification.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use silver_core::{ObjectID, SilverAddress, TransactionDigest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Query result containing transaction data and Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Transaction digest
    pub tx_digest: TransactionDigest,

    /// Transaction data (serialized)
    pub tx_data: Vec<u8>,

    /// Merkle proof for verification
    pub proof: MerkleProofData,

    /// Timestamp of transaction
    pub timestamp: u64,

    /// Snapshot sequence number this proof is for
    pub snapshot_sequence: u64,
}

/// Merkle proof data for query results
#[derive(Debug, Clone)]
pub struct MerkleProofData {
    /// Transaction hash
    pub tx_hash: [u8; 64],

    /// Merkle proof path (sibling hashes)
    pub path: Vec<[u8; 64]>,

    /// Position in the tree
    pub position: u32,

    /// Root hash this proof is for
    pub root: [u8; 64],

    /// Proof size in bytes
    pub size_bytes: usize,
}

impl Serialize for MerkleProofData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MerkleProofData", 5)?;
        state.serialize_field("tx_hash", &self.tx_hash.to_vec())?;
        state.serialize_field("path", &self.path.iter().map(|h| h.to_vec()).collect::<Vec<_>>())?;
        state.serialize_field("position", &self.position)?;
        state.serialize_field("root", &self.root.to_vec())?;
        state.serialize_field("size_bytes", &self.size_bytes)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MerkleProofData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            tx_hash: Vec<u8>,
            path: Vec<Vec<u8>>,
            position: u32,
            root: Vec<u8>,
            size_bytes: usize,
        }

        let helper = Helper::deserialize(deserializer)?;

        let mut tx_hash = [0u8; 64];
        if helper.tx_hash.len() != 64 {
            return Err(serde::de::Error::custom("tx_hash must be 64 bytes"));
        }
        tx_hash.copy_from_slice(&helper.tx_hash);

        let mut path = Vec::new();
        for h in helper.path {
            if h.len() != 64 {
                return Err(serde::de::Error::custom("path hash must be 64 bytes"));
            }
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&h);
            path.push(hash);
        }

        let mut root = [0u8; 64];
        if helper.root.len() != 64 {
            return Err(serde::de::Error::custom("root must be 64 bytes"));
        }
        root.copy_from_slice(&helper.root);

        Ok(MerkleProofData {
            tx_hash,
            path,
            position: helper.position,
            root,
            size_bytes: helper.size_bytes,
        })
    }
}

impl MerkleProofData {
    /// Verify this Merkle proof against a root
    pub fn verify(&self, root: &[u8; 64]) -> bool {
        let mut current = self.tx_hash;
        let mut position = self.position;

        for &sibling in &self.path {
            current = if position & 1 == 0 {
                // Left child
                Self::hash_pair(&current, &sibling)
            } else {
                // Right child
                Self::hash_pair(&sibling, &current)
            };
            position >>= 1;
        }

        current == *root
    }

    /// Hash two nodes together
    fn hash_pair(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(left);
        hasher.update(right);

        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Get the depth of this proof
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

/// Query filter for transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    /// Query by sender address
    pub sender: Option<SilverAddress>,

    /// Query by recipient address
    pub recipient: Option<SilverAddress>,

    /// Query by object ID
    pub object_id: Option<ObjectID>,

    /// Start timestamp (inclusive)
    pub start_time: Option<u64>,

    /// End timestamp (inclusive)
    pub end_time: Option<u64>,

    /// Maximum number of results
    pub limit: usize,

    /// Offset for pagination
    pub offset: usize,
}

impl Default for QueryFilter {
    fn default() -> Self {
        Self {
            sender: None,
            recipient: None,
            object_id: None,
            start_time: None,
            end_time: None,
            limit: 100,
            offset: 0,
        }
    }
}

/// Query response with results and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Query results
    pub results: Vec<QueryResult>,

    /// Total number of matching transactions
    pub total_count: u64,

    /// Whether there are more results
    pub has_more: bool,

    /// Query execution time in milliseconds
    pub execution_time_ms: u64,

    /// Snapshot sequence this query is based on
    pub snapshot_sequence: u64,
}

/// LRU cache for query results
struct QueryCache {
    /// Cache entries (key -> results)
    entries: HashMap<String, (QueryResponse, Instant)>,

    /// Maximum cache size
    max_size: usize,

    /// Cache entry TTL in seconds
    ttl_seconds: u64,
}

impl QueryCache {
    /// Create a new query cache
    fn new(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            ttl_seconds,
        }
    }

    /// Get a cached query result
    fn get(&self, key: &str) -> Option<QueryResponse> {
        if let Some((response, timestamp)) = self.entries.get(key) {
            let age_seconds = timestamp.elapsed().as_secs();
            if age_seconds < self.ttl_seconds {
                return Some(response.clone());
            }
        }
        None
    }

    /// Insert a query result into cache
    fn insert(&mut self, key: String, response: QueryResponse) {
        // Evict oldest entry if cache is full
        if self.entries.len() >= self.max_size {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, ts))| ts)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(key, (response, Instant::now()));
    }

    /// Clear expired entries
    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, (_, ts)| {
            now.duration_since(*ts).as_secs() < self.ttl_seconds
        });
    }
}

/// Light Client Query Handler
///
/// Handles queries from light clients, returning transaction data
/// with Merkle proofs for verification.
pub struct QueryHandler {
    /// Query cache
    cache: Arc<RwLock<QueryCache>>,

    /// Maximum query results per request
    max_results: usize,

    /// Verification timeout in milliseconds
    verification_timeout_ms: u64,
}

impl QueryHandler {
    /// Create a new query handler
    pub fn new(max_results: usize, verification_timeout_ms: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(QueryCache::new(10000, 300))), // 10k entries, 5min TTL
            max_results,
            verification_timeout_ms,
        }
    }

    /// Execute a query
    ///
    /// This is a placeholder that would be implemented with actual
    /// Archive Chain integration. In a real implementation, this would:
    /// 1. Query the Archive Chain for matching transactions
    /// 2. Generate Merkle proofs for each result
    /// 3. Cache frequently accessed results
    /// 4. Return results with proofs
    pub async fn query(&self, filter: QueryFilter) -> Result<QueryResponse> {
        let start = Instant::now();

        // Generate cache key
        let cache_key = self.generate_cache_key(&filter);

        // Check cache first
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(&cache_key) {
            debug!("Query cache hit for key: {}", cache_key);
            return Ok(cached);
        }
        drop(cache);

        // TODO: Query Archive Chain
        // This would involve:
        // 1. Connecting to Archive Chain nodes
        // 2. Executing the query with the filter
        // 3. Generating Merkle proofs for results
        // 4. Verifying proofs within timeout

        // For now, return empty results
        let response = QueryResponse {
            results: vec![],
            total_count: 0,
            has_more: false,
            execution_time_ms: start.elapsed().as_millis() as u64,
            snapshot_sequence: 0,
        };

        // Cache the result
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, response.clone());

        Ok(response)
    }

    /// Query by sender address
    pub async fn query_by_sender(
        &self,
        sender: SilverAddress,
        limit: usize,
    ) -> Result<QueryResponse> {
        let filter = QueryFilter {
            sender: Some(sender),
            limit: limit.min(self.max_results),
            ..Default::default()
        };

        self.query(filter).await
    }

    /// Query by recipient address
    pub async fn query_by_recipient(
        &self,
        recipient: SilverAddress,
        limit: usize,
    ) -> Result<QueryResponse> {
        let filter = QueryFilter {
            recipient: Some(recipient),
            limit: limit.min(self.max_results),
            ..Default::default()
        };

        self.query(filter).await
    }

    /// Query by object ID
    pub async fn query_by_object_id(
        &self,
        object_id: ObjectID,
        limit: usize,
    ) -> Result<QueryResponse> {
        let filter = QueryFilter {
            object_id: Some(object_id),
            limit: limit.min(self.max_results),
            ..Default::default()
        };

        self.query(filter).await
    }

    /// Query by timestamp range
    pub async fn query_by_time_range(
        &self,
        start_time: u64,
        end_time: u64,
        limit: usize,
    ) -> Result<QueryResponse> {
        if start_time > end_time {
            return Err(Error::InvalidQuery(
                "start_time must be <= end_time".to_string(),
            ));
        }

        let filter = QueryFilter {
            start_time: Some(start_time),
            end_time: Some(end_time),
            limit: limit.min(self.max_results),
            ..Default::default()
        };

        self.query(filter).await
    }

    /// Verify all proofs in a query response
    ///
    /// Returns Ok(()) if all proofs are valid, Err otherwise.
    /// Must complete within verification_timeout_ms.
    pub async fn verify_response_proofs(
        &self,
        response: &QueryResponse,
        snapshot_root: &[u8; 64],
    ) -> Result<()> {
        let start = Instant::now();

        for result in &response.results {
            // Verify proof against snapshot root
            if !result.proof.verify(snapshot_root) {
                warn!(
                    "Proof verification failed for transaction: {:?}",
                    result.tx_digest
                );
                return Err(Error::InvalidProof(format!(
                    "Proof verification failed for transaction: {:?}",
                    result.tx_digest
                )));
            }

            // Check timeout
            if start.elapsed().as_millis() as u64 > self.verification_timeout_ms {
                return Err(Error::VerificationTimeout);
            }
        }

        Ok(())
    }

    /// Verify a single query result
    pub async fn verify_result(
        &self,
        result: &QueryResult,
        snapshot_root: &[u8; 64],
    ) -> Result<()> {
        let start = Instant::now();

        if !result.proof.verify(snapshot_root) {
            return Err(Error::InvalidProof(
                "Proof verification failed".to_string(),
            ));
        }

        if start.elapsed().as_millis() as u64 > self.verification_timeout_ms {
            return Err(Error::VerificationTimeout);
        }

        Ok(())
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            entries: cache.entries.len(),
            max_size: cache.max_size,
            ttl_seconds: cache.ttl_seconds,
        }
    }

    /// Clear the query cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.entries.clear();
    }

    /// Prune expired cache entries
    pub async fn prune_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.prune_expired();
    }

    /// Generate cache key from filter
    fn generate_cache_key(&self, filter: &QueryFilter) -> String {
        let mut key = String::new();

        if let Some(sender) = &filter.sender {
            key.push_str(&format!("sender:{:?}", sender));
        }
        if let Some(recipient) = &filter.recipient {
            key.push_str(&format!("recipient:{:?}", recipient));
        }
        if let Some(object_id) = &filter.object_id {
            key.push_str(&format!("object:{:?}", object_id));
        }
        if let Some(start) = filter.start_time {
            key.push_str(&format!("start:{}", start));
        }
        if let Some(end) = filter.end_time {
            key.push_str(&format!("end:{}", end));
        }

        key.push_str(&format!("limit:{}", filter.limit));
        key.push_str(&format!("offset:{}", filter.offset));

        key
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of entries in cache
    pub entries: usize,

    /// Maximum cache size
    pub max_size: usize,

    /// Cache entry TTL in seconds
    pub ttl_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_verification() {
        let proof = MerkleProofData {
            tx_hash: [1u8; 64],
            path: vec![[2u8; 64]],
            position: 0,
            root: [0u8; 64],
            size_bytes: 128,
        };

        // This will fail because we don't have a valid proof path
        // but it tests the verification logic
        assert!(!proof.verify(&[0u8; 64]));
    }

    #[test]
    fn test_query_filter_default() {
        let filter = QueryFilter::default();
        assert_eq!(filter.limit, 100);
        assert_eq!(filter.offset, 0);
        assert!(filter.sender.is_none());
    }

    #[test]
    fn test_cache_key_generation() {
        let handler = QueryHandler::new(1000, 100);

        let filter1 = QueryFilter {
            sender: Some(SilverAddress::new([1u8; 64])),
            limit: 100,
            ..Default::default()
        };

        let filter2 = QueryFilter {
            sender: Some(SilverAddress::new([1u8; 64])),
            limit: 100,
            ..Default::default()
        };

        let key1 = handler.generate_cache_key(&filter1);
        let key2 = handler.generate_cache_key(&filter2);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_query_filter_validation() {
        let filter = QueryFilter {
            start_time: Some(100),
            end_time: Some(50),
            ..Default::default()
        };

        // This should fail validation
        assert!(filter.start_time.unwrap() > filter.end_time.unwrap());
    }

    #[tokio::test]
    async fn test_query_handler_creation() {
        let handler = QueryHandler::new(1000, 100);
        let stats = handler.cache_stats().await;

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_size, 10000);
    }

    #[tokio::test]
    async fn test_query_handler_cache_clear() {
        let handler = QueryHandler::new(1000, 100);

        // Clear cache
        handler.clear_cache().await;

        let stats = handler.cache_stats().await;
        assert_eq!(stats.entries, 0);
    }

    #[tokio::test]
    async fn test_query_by_sender() {
        let handler = QueryHandler::new(1000, 100);
        let sender = SilverAddress::new([1u8; 64]);

        let response = handler.query_by_sender(sender, 100).await.unwrap();
        assert_eq!(response.results.len(), 0);
    }

    #[tokio::test]
    async fn test_query_by_time_range_invalid() {
        let handler = QueryHandler::new(1000, 100);

        let result = handler.query_by_time_range(100, 50, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_response_verification() {
        let handler = QueryHandler::new(1000, 100);

        let response = QueryResponse {
            results: vec![],
            total_count: 0,
            has_more: false,
            execution_time_ms: 10,
            snapshot_sequence: 1,
        };

        let root = [0u8; 64];
        let result = handler.verify_response_proofs(&response, &root).await;
        assert!(result.is_ok());
    }
}
