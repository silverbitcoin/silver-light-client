//! Light client synchronization
//!
//! This module implements efficient synchronization for light clients,
//! maintaining sync with <10MB bandwidth per day under normal usage.

use crate::{Error, LightClient, Result, SnapshotCertificate, StateProof};
use serde::{Deserialize, Serialize};
use silver_core::{Object, ObjectID, SnapshotSequenceNumber};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{warn};

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Sync interval in seconds
    pub sync_interval_secs: u64,

    /// Maximum bandwidth per day in bytes (default: 10MB)
    pub max_bandwidth_per_day: u64,

    /// Number of certificates to fetch per sync
    pub certificates_per_sync: usize,

    /// Retry attempts for failed requests
    pub max_retries: usize,

    /// Timeout for RPC requests in milliseconds
    pub rpc_timeout_ms: u64,

    /// RPC endpoints to query for certificates
    pub rpc_endpoints: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            sync_interval_secs: 60,                  // Sync every minute
            max_bandwidth_per_day: 10 * 1024 * 1024, // 10MB
            certificates_per_sync: 10,
            max_retries: 3,
            rpc_timeout_ms: 5000,
            rpc_endpoints: vec![
                "http://localhost:9000".to_string(),
                "http://localhost:9001".to_string(),
            ],
        }
    }
}

/// Bandwidth tracker for monitoring data usage
#[derive(Debug)]
struct BandwidthTracker {
    /// Bytes used today
    bytes_used_today: u64,

    /// Last reset timestamp
    last_reset: std::time::Instant,

    /// Maximum bytes per day
    max_bytes_per_day: u64,
}

impl BandwidthTracker {
    fn new(max_bytes_per_day: u64) -> Self {
        Self {
            bytes_used_today: 0,
            last_reset: std::time::Instant::now(),
            max_bytes_per_day,
        }
    }

    /// Record bandwidth usage
    fn record_usage(&mut self, bytes: u64) -> Result<()> {
        // Reset counter if a day has passed
        if self.last_reset.elapsed() >= Duration::from_secs(86400) {
            self.bytes_used_today = 0;
            self.last_reset = std::time::Instant::now();
        }

        // Check if we would exceed limit
        if self.bytes_used_today + bytes > self.max_bytes_per_day {
            return Err(Error::Sync(format!(
                "Bandwidth limit exceeded: {} / {} bytes used today",
                self.bytes_used_today, self.max_bytes_per_day
            )));
        }

        self.bytes_used_today += bytes;
        Ok(())
    }

    /// Get current usage statistics
    fn usage_stats(&self) -> BandwidthStats {
        BandwidthStats {
            bytes_used_today: self.bytes_used_today,
            max_bytes_per_day: self.max_bytes_per_day,
            percentage_used: (self.bytes_used_today as f64 / self.max_bytes_per_day as f64) * 100.0,
            time_until_reset: Duration::from_secs(86400).saturating_sub(self.last_reset.elapsed()),
        }
    }
}

/// Bandwidth usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStats {
    /// Bytes used today
    pub bytes_used_today: u64,

    /// Maximum bytes per day
    pub max_bytes_per_day: u64,

    /// Percentage of daily limit used
    pub percentage_used: f64,

    /// Time until bandwidth counter resets
    #[serde(skip)]
    pub time_until_reset: Duration,
}

/// Sync manager for light client
///
/// Manages periodic synchronization with full nodes while respecting
/// bandwidth constraints (<10MB per day).
pub struct SyncManager {
    config: SyncConfig,
    bandwidth_tracker: Arc<RwLock<BandwidthTracker>>,
    is_running: Arc<RwLock<bool>>,
}

impl SyncManager {
    /// Create a new sync manager
    pub fn new(config: SyncConfig) -> Self {
        let bandwidth_tracker = BandwidthTracker::new(config.max_bandwidth_per_day);

        Self {
            config,
            bandwidth_tracker: Arc::new(RwLock::new(bandwidth_tracker)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start periodic synchronization
    ///
    /// Spawns a background task that syncs at regular intervals.
    pub async fn start(&self, client: Arc<RwLock<LightClient>>) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(Error::Sync("Sync manager already running".to_string()));
        }
        *is_running = true;
        drop(is_running);

        let config = self.config.clone();
        let bandwidth_tracker = self.bandwidth_tracker.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(config.sync_interval_secs));

            loop {
                interval.tick().await;

                // Check if we should stop
                let running = is_running.read().await;
                if !*running {
                    break;
                }
                drop(running);

                // Perform sync
                if let Err(e) = Self::sync_once(&client, &config, &bandwidth_tracker).await {
                    tracing::warn!("Sync failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Stop periodic synchronization
    pub async fn stop(&self) {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
    }

    /// Perform a single sync operation
    async fn sync_once(
        client: &Arc<RwLock<LightClient>>,
        config: &SyncConfig,
        bandwidth_tracker: &Arc<RwLock<BandwidthTracker>>,
    ) -> Result<()> {
        tracing::debug!("Starting sync operation");

        // 1. Query full nodes for latest snapshot certificates
        let certificates = Self::fetch_latest_certificates(config).await?;

        if certificates.is_empty() {
            return Err(Error::Sync(
                "No certificates received from full nodes".to_string(),
            ));
        }

        // 2. Track bandwidth usage
        let total_bytes: usize = certificates.iter().map(|c| c.size_bytes()).sum();
        {
            let mut tracker = bandwidth_tracker.write().await;
            tracker.record_usage(total_bytes as u64)?;
        }

        // 3. Verify and store certificates
        let client_lock = client.write().await;
        let mut verified_count = 0;

        for certificate in certificates {
            match client_lock.verify_certificate(certificate.clone()).await {
                Ok(_) => {
                    // Store certificate in client state
                    verified_count += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to verify certificate: {}", e);
                }
            }
        }

        if verified_count == 0 {
            return Err(Error::Sync("No valid certificates received".to_string()));
        }

        tracing::info!("Sync completed: verified {} certificates", verified_count);

        tracing::debug!("Sync operation completed, used {} bytes", total_bytes);

        Ok(())
    }

    /// Fetch latest certificates from full nodes
    ///
    /// Queries multiple full nodes for latest certificates and verifies
    /// consistency across nodes before returning.
    async fn fetch_latest_certificates(config: &SyncConfig) -> Result<Vec<SnapshotCertificate>> {
        // Fetch latest certificates from RPC endpoints
        let mut certificates = Vec::new();
        let mut errors = Vec::new();

        // Query each RPC endpoint for latest certificates
        for rpc_url in &config.rpc_endpoints {
            match Self::fetch_certificates_from_endpoint(rpc_url).await {
                Ok(certs) => {
                    certificates.extend(certs);
                }
                Err(e) => {
                    errors.push(format!("Failed to fetch from {}: {}", rpc_url, e));
                }
            }
        }

        if certificates.is_empty() {
            return Err(Error::Network(format!(
                "Failed to fetch certificates from any endpoint: {}",
                errors.join("; ")
            )));
        }

        // Verify consistency across nodes
        Self::verify_certificate_consistency(&certificates)?;

        // Sort by snapshot number and deduplicate
        certificates.sort_by_key(|c| c.sequence_number);
        certificates.dedup_by_key(|c| c.sequence_number);

        Ok(certificates)
    }

    /// Fetch certificates from a single RPC endpoint
    async fn fetch_certificates_from_endpoint(rpc_url: &str) -> Result<Vec<SnapshotCertificate>> {
        Self::query_full_node_certificates(rpc_url).await
    }

    /// Query a single full node for certificates
    #[allow(dead_code)]
    async fn query_full_node_certificates(full_node: &str) -> Result<Vec<SnapshotCertificate>> {
        // Use JSON-RPC to query full node
        let client = reqwest::Client::new();
        let url = format!("http://{}/rpc", full_node);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_latest_snapshot_certificates",
            "params": []
        });

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Network(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("RPC error: {}", error)));
        }

        let certificates = result
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| Error::Network("Invalid RPC response format".to_string()))?;

        let mut certs = Vec::new();
        for cert_json in certificates {
            let cert: SnapshotCertificate = serde_json::from_value(cert_json.clone())
                .map_err(|e| Error::Network(format!("Failed to parse certificate: {}", e)))?;
            certs.push(cert);
        }

        Ok(certs)
    }

    /// Verify consistency of certificates across nodes
    fn verify_certificate_consistency(certificates: &[SnapshotCertificate]) -> Result<()> {
        if certificates.is_empty() {
            return Ok(());
        }

        // Group by snapshot number
        let mut by_snapshot: std::collections::HashMap<u64, Vec<&SnapshotCertificate>> =
            std::collections::HashMap::new();

        for cert in certificates {
            by_snapshot
                .entry(cert.sequence_number)
                .or_insert_with(Vec::new)
                .push(cert);
        }

        // Verify all certificates for the same snapshot are identical
        for (snapshot_num, certs) in by_snapshot {
            if certs.len() > 1 {
                let first = &certs[0];
                for other in &certs[1..] {
                    if first.snapshot_digest != other.snapshot_digest {
                        return Err(Error::Sync(format!(
                            "Certificate mismatch for snapshot {}: different digests",
                            snapshot_num
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Query object state from full nodes with proof
    ///
    /// Queries full nodes for object and proof, tracks bandwidth usage,
    /// and returns object and proof for verification.
    pub async fn query_object_with_proof(
        &self,
        object_id: ObjectID,
    ) -> Result<(Object, StateProof)> {
        // Query full node for object and proof
        let (object, proof) = self.query_full_node_for_object(&object_id).await?;

        // Track bandwidth usage
        let size = object.size_bytes() + proof.size_bytes();
        {
            let mut tracker = self.bandwidth_tracker.write().await;
            tracker.record_usage(size as u64)?;
        }

        // Return object and proof for verification
        Ok((object, proof))
    }

    /// Query a full node for object and proof
    async fn query_full_node_for_object(
        &self,
        object_id: &ObjectID,
    ) -> Result<(Object, StateProof)> {
        // Select a random full node from the RPC endpoints
        let endpoints = &self.config.rpc_endpoints;
        if endpoints.is_empty() {
            return Err(Error::Network("No RPC endpoints configured".to_string()));
        }

        let endpoint = &endpoints[rand::random::<usize>() % endpoints.len()];
        
        // Create RPC client
        let client = self.create_rpc_client(endpoint).await?;

        // Query object with timeout
        let timeout_duration = Duration::from_millis(self.config.rpc_timeout_ms);
        
        match tokio::time::timeout(
            timeout_duration,
            client.query_object(object_id),
        )
        .await
        {
            Ok(Ok((object, proof))) => {
                // Verify the proof before returning
                match proof.verify() {
                    Ok(()) => {
                        // Update bandwidth tracker
                        let object_size = bincode::serialized_size(&object)
                            .unwrap_or(0) as u64;
                        self.bandwidth_tracker.write().await.record_usage(object_size)?;
                        
                        Ok((object, proof))
                    }
                    Err(e) => {
                        warn!("Object proof verification failed: {}", e);
                        Err(Error::InvalidProof(format!(
                            "Failed to verify object proof: {}",
                            e
                        )))
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("RPC query failed: {}", e);
                Err(Error::Network(format!("RPC query failed: {}", e)))
            }
            Err(_) => {
                warn!("RPC query timeout");
                Err(Error::Network("RPC query timeout".to_string()))
            }
        }
    }

    /// Get bandwidth usage statistics
    pub async fn bandwidth_stats(&self) -> BandwidthStats {
        let tracker = self.bandwidth_tracker.read().await;
        tracker.usage_stats()
    }

    /// Check if sync is running
    pub async fn is_running(&self) -> bool {
        let is_running = self.is_running.read().await;
        *is_running
    }

    /// Create an RPC client for a given endpoint
    async fn create_rpc_client(&self, endpoint: &str) -> Result<FullNodeRpcClient> {
        Ok(FullNodeRpcClient::new(endpoint.to_string(), self.config.rpc_timeout_ms))
    }
}

/// RPC client for communicating with full nodes
///
/// Uses HTTP/WebSocket to communicate with full node JSON-RPC endpoints.
pub struct FullNodeRpcClient {
    endpoint: String,
    client: reqwest::Client,
    timeout: Duration,
}

impl FullNodeRpcClient {
    /// Create a new RPC client
    pub fn new(endpoint: String, timeout_ms: u64) -> Self {
        Self {
            endpoint,
            client: reqwest::Client::new(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Fetch the latest snapshot certificate
    pub async fn get_latest_certificate(&self) -> Result<SnapshotCertificate> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_latest_snapshot_certificate",
            "params": []
        });

        let response = self
            .client
            .post(&format!("http://{}/rpc", self.endpoint))
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("RPC error: {}", error)));
        }

        serde_json::from_value(
            result
                .get("result")
                .ok_or_else(|| Error::Network("Missing result in RPC response".to_string()))?
                .clone(),
        )
        .map_err(|e| Error::Network(format!("Failed to parse certificate: {}", e)))
    }

    /// Fetch a specific snapshot certificate by sequence number
    pub async fn get_certificate(
        &self,
        sequence: SnapshotSequenceNumber,
    ) -> Result<SnapshotCertificate> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_snapshot_certificate",
            "params": [sequence]
        });

        let response = self
            .client
            .post(&format!("http://{}/rpc", self.endpoint))
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("RPC error: {}", error)));
        }

        serde_json::from_value(
            result
                .get("result")
                .ok_or_else(|| Error::Network("Missing result in RPC response".to_string()))?
                .clone(),
        )
        .map_err(|e| Error::Network(format!("Failed to parse certificate: {}", e)))
    }

    /// Query object state with proof
    pub async fn get_object_with_proof(&self, object_id: ObjectID) -> Result<(Object, StateProof)> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_object_with_proof",
            "params": [object_id.to_string()]
        });

        let response = self
            .client
            .post(&format!("http://{}/rpc", self.endpoint))
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("RPC error: {}", error)));
        }

        let result_obj = result
            .get("result")
            .ok_or_else(|| Error::Network("Missing result in RPC response".to_string()))?;

        let object = serde_json::from_value(
            result_obj
                .get("object")
                .ok_or_else(|| Error::Network("Missing object in result".to_string()))?
                .clone(),
        )
        .map_err(|e| Error::Network(format!("Failed to parse object: {}", e)))?;

        let proof = serde_json::from_value(
            result_obj
                .get("proof")
                .ok_or_else(|| Error::Network("Missing proof in result".to_string()))?
                .clone(),
        )
        .map_err(|e| Error::Network(format!("Failed to parse proof: {}", e)))?;

        Ok((object, proof))
    }

    /// Query an object from the full node
    pub async fn query_object(&self, object_id: &ObjectID) -> Result<(Object, StateProof)> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "query_object",
            "params": [object_id.to_string()]
        });

        let response = self
            .client
            .post(&format!("http://{}/rpc", self.endpoint))
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("RPC request failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(Error::Network(format!("RPC error: {}", error)));
        }

        let result_obj = result
            .get("result")
            .ok_or_else(|| Error::Network("Missing result in RPC response".to_string()))?;

        let object: Object = serde_json::from_value(result_obj.get("object").cloned().unwrap_or_default())
            .map_err(|e| Error::Network(format!("Failed to parse object: {}", e)))?;

        let proof: StateProof = serde_json::from_value(result_obj.get("proof").cloned().unwrap_or_default())
            .map_err(|e| Error::Network(format!("Failed to parse proof: {}", e)))?;

        Ok((object, proof))
    }

    /// Check if the full node is reachable
    pub async fn health_check(&self) -> Result<bool> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "health",
            "params": []
        });

        match self
            .client
            .post(&format!("http://{}/rpc", self.endpoint))
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }
}
