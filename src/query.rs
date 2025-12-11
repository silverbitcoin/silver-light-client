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
use silver_core::{ObjectID, SilverAddress, Transaction, TransactionDigest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Merkle tree metadata for proof generation
#[derive(Debug, Clone)]
struct MerkleTreeMetadata {
    /// Position of transaction in the tree
    position: u32,

    /// Depth of the Merkle tree
    tree_depth: usize,

    /// Root hash of the snapshot
    snapshot_root: [u8; 64],

    /// Sibling hashes for the proof path
    siblings: Vec<[u8; 64]>,
}

impl MerkleTreeMetadata {
    /// Get sibling hash at a specific tree level
    fn get_sibling_at_level(&self, level: usize) -> Option<[u8; 64]> {
        if level < self.siblings.len() {
            Some(self.siblings[level])
        } else {
            None
        }
    }
}

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
        state.serialize_field(
            "path",
            &self.path.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
        )?;
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
        self.entries
            .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < self.ttl_seconds);
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

    /// Archive node endpoints
    archive_nodes: Vec<String>,
}

impl QueryHandler {
    /// Create a new query handler
    pub fn new(max_results: usize, verification_timeout_ms: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(QueryCache::new(10000, 300))), // 10k entries, 5min TTL
            max_results,
            verification_timeout_ms,
            archive_nodes: Vec::new(),
        }
    }

    /// Set archive node endpoints
    pub fn with_archive_nodes(mut self, nodes: Vec<String>) -> Self {
        self.archive_nodes = nodes;
        self
    }

    /// Execute a query
    ///
    /// Queries the Archive Chain for matching transactions, generates Merkle proofs,
    /// and returns results with proofs for verification.
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

        // Query Archive Chain for matching transactions
        let transactions = self.query_archive_chain(&filter).await?;

        // Generate Merkle proofs for each result
        let mut results = Vec::new();
        for tx in transactions {
            let proof = self.generate_merkle_proof(&tx).await?;
            let tx_digest = tx.digest();
            let tx_data = bincode::serialize(&tx)?;

            results.push(QueryResult {
                tx_digest,
                tx_data,
                proof,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                snapshot_sequence: 0, // Will be set by caller
            });
        }

        // Verify proofs within timeout
        let verification_start = std::time::Instant::now();
        for _result in &results {
            // Proof verification would happen here
            // self.verifier.verify_merkle_proof(&_result.proof)?;

            if verification_start.elapsed()
                > std::time::Duration::from_millis(self.verification_timeout_ms)
            {
                return Err(Error::VerificationTimeout);
            }
        }

        let response = QueryResponse {
            results: results.clone(),
            total_count: results.len() as u64,
            has_more: false,
            execution_time_ms: start.elapsed().as_millis() as u64,
            snapshot_sequence: 0,
        };

        // Cache the response
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, response.clone());

        Ok(response)
    }

    /// Query Archive Chain for matching transactions
    async fn query_archive_chain(&self, filter: &QueryFilter) -> Result<Vec<Transaction>> {
        // Query archive chain nodes for matching transactions
        let mut all_transactions = Vec::new();
        let mut errors = Vec::new();

        for archive_node in &self.archive_nodes {
            match self.query_archive_node(archive_node, filter).await {
                Ok(transactions) => {
                    all_transactions.extend(transactions);
                }
                Err(e) => {
                    errors.push(format!("Failed to query {}: {}", archive_node, e));
                }
            }
        }

        if all_transactions.is_empty() && !errors.is_empty() {
            return Err(Error::Network(format!(
                "Failed to query archive chain: {}",
                errors.join("; ")
            )));
        }

        // Remove duplicates and sort
        all_transactions.sort_by_key(|tx| tx.digest());
        all_transactions.dedup_by_key(|tx| tx.digest());

        Ok(all_transactions)
    }

    /// Query a single Archive Chain node
    #[allow(dead_code)]
    async fn query_archive_node(
        &self,
        archive_node: &str,
        filter: &QueryFilter,
    ) -> Result<Vec<Transaction>> {
        // Use JSON-RPC to query Archive Chain
        let client = reqwest::Client::new();
        let url = format!("http://{}/rpc", archive_node);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "query_transactions",
            "params": [filter]
        });

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::InvalidQuery(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::InvalidQuery(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::InvalidQuery(format!("RPC error: {}", error)));
        }

        let transactions = result
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| Error::InvalidQuery("Invalid RPC response format".to_string()))?;

        let mut txs = Vec::new();
        for tx_json in transactions {
            let tx: Transaction = serde_json::from_value(tx_json.clone())
                .map_err(|e| Error::InvalidQuery(format!("Failed to parse transaction: {}", e)))?;
            txs.push(tx);
        }

        Ok(txs)
    }

    /// Generate Merkle proof for a transaction
    ///
    /// Computes the Merkle proof path from transaction leaf to snapshot root
    /// using Blake3 hashing for cryptographic security.
    ///
    /// This implementation:
    /// 1. Computes the transaction hash using Blake3-512
    /// 2. Queries the Archive Chain for the transaction's position in the Merkle tree
    /// 3. Retrieves sibling hashes from the tree structure
    /// 4. Builds the complete proof path from leaf to root
    /// 5. Verifies the path leads to the snapshot root
    async fn generate_merkle_proof(
        &self,
        transaction: &silver_core::Transaction,
    ) -> Result<MerkleProofData> {
        // Step 1: Compute transaction hash using Blake3-512
        let tx_digest = transaction.digest();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&tx_digest.0);
        let mut leaf_hash = [0u8; 64];
        hasher.finalize_xof().fill(&mut leaf_hash);

        // Step 2: Query Archive Chain for transaction metadata
        // This includes: position in tree, snapshot number, and sibling hashes
        let archive_metadata = self.query_archive_for_merkle_metadata(&tx_digest).await?;

        // Step 3: Build the Merkle proof path
        // The path contains sibling hashes at each level of the tree
        let mut proof_path = Vec::new();

        // For each level in the tree, add the sibling hash
        for level in 0..archive_metadata.tree_depth {
            if let Some(sibling_hash) = archive_metadata.get_sibling_at_level(level) {
                proof_path.push(sibling_hash);
            }
        }

        // Step 4: Calculate proof size
        let size_bytes = 64 + (proof_path.len() * 64) + 4 + 64; // leaf + path + position + root

        // Step 5: Create and return the Merkle proof
        let proof = MerkleProofData {
            tx_hash: leaf_hash,
            path: proof_path,
            position: archive_metadata.position,
            root: archive_metadata.snapshot_root,
            size_bytes,
        };

        // Step 6: Verify the proof is valid (sanity check)
        if !proof.verify(&archive_metadata.snapshot_root) {
            return Err(Error::InvalidProof(
                "Generated Merkle proof failed verification".to_string(),
            ));
        }

        Ok(proof)
    }

    /// Query Archive Chain for Merkle tree metadata
    ///
    /// Retrieves the transaction's position in the Merkle tree,
    /// tree depth, sibling hashes, and snapshot root.
    async fn query_archive_for_merkle_metadata(
        &self,
        tx_digest: &silver_core::TransactionDigest,
    ) -> Result<MerkleTreeMetadata> {
        // Use JSON-RPC to query Archive Chain for Merkle metadata
        let client = reqwest::Client::new();

        // Query from Archive Chain node (configurable via environment or config)
        let archive_url = std::env::var("ARCHIVE_CHAIN_URL")
            .unwrap_or_else(|_| "http://localhost:9546/rpc".to_string());

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_merkle_proof_metadata",
            "params": [tx_digest.to_string()]
        });

        let response = client
            .post(archive_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Network(format!("Failed to query Archive Chain: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse Archive response: {}", e)))?;

        // Check for RPC errors
        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("Archive Chain error: {}", error)));
        }

        // Parse the result
        let result_obj = result
            .get("result")
            .ok_or_else(|| Error::Network("Missing result in Archive response".to_string()))?;

        // Extract metadata fields
        let position = result_obj
            .get("position")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::InvalidProof("Missing position in metadata".to_string()))?
            as u32;

        let tree_depth = result_obj
            .get("tree_depth")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::InvalidProof("Missing tree_depth in metadata".to_string()))?
            as usize;

        let snapshot_root_str = result_obj
            .get("snapshot_root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidProof("Missing snapshot_root in metadata".to_string()))?;

        let mut snapshot_root = [0u8; 64];
        let root_bytes = hex::decode(snapshot_root_str)
            .map_err(|e| Error::InvalidProof(format!("Invalid snapshot_root hex: {}", e)))?;
        if root_bytes.len() != 64 {
            return Err(Error::InvalidProof(
                "snapshot_root must be 64 bytes".to_string(),
            ));
        }
        snapshot_root.copy_from_slice(&root_bytes);

        // Extract sibling hashes
        let siblings_array = result_obj
            .get("siblings")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::InvalidProof("Missing siblings in metadata".to_string()))?;

        let mut siblings = Vec::new();
        for sibling_str in siblings_array {
            let sibling_hex = sibling_str
                .as_str()
                .ok_or_else(|| Error::InvalidProof("Sibling is not a string".to_string()))?;

            let mut sibling = [0u8; 64];
            let sibling_bytes = hex::decode(sibling_hex)
                .map_err(|e| Error::InvalidProof(format!("Invalid sibling hex: {}", e)))?;
            if sibling_bytes.len() != 64 {
                return Err(Error::InvalidProof("Sibling must be 64 bytes".to_string()));
            }
            sibling.copy_from_slice(&sibling_bytes);
            siblings.push(sibling);
        }

        Ok(MerkleTreeMetadata {
            position,
            tree_depth,
            snapshot_root,
            siblings,
        })
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
            return Err(Error::InvalidProof("Proof verification failed".to_string()));
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
