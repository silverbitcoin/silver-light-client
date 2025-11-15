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
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            sync_interval_secs: 60, // Sync every minute
            max_bandwidth_per_day: 10 * 1024 * 1024, // 10MB
            certificates_per_sync: 10,
            max_retries: 3,
            rpc_timeout_ms: 5000,
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
            time_until_reset: Duration::from_secs(86400)
                .saturating_sub(self.last_reset.elapsed()),
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
        // TODO: Implement actual RPC calls to full nodes
        // For now, this is a placeholder that shows the structure

        tracing::debug!("Starting sync operation");

        // 1. Query full node for latest snapshot certificate
        let certificates = Self::fetch_latest_certificates(config).await?;

        // 2. Track bandwidth usage
        let total_bytes: usize = certificates.iter().map(|c| c.size_bytes()).sum();
        {
            let mut tracker = bandwidth_tracker.write().await;
            tracker.record_usage(total_bytes as u64)?;
        }

        // 3. Verify and store certificates
        let client_lock = client.write().await;
        for certificate in certificates {
            if let Err(e) = client_lock.verify_certificate(certificate).await {
                tracing::warn!("Failed to verify certificate: {}", e);
            }
        }

        tracing::debug!("Sync operation completed, used {} bytes", total_bytes);

        Ok(())
    }

    /// Fetch latest certificates from full nodes
    ///
    /// This is a placeholder for actual RPC implementation.
    async fn fetch_latest_certificates(
        _config: &SyncConfig,
    ) -> Result<Vec<SnapshotCertificate>> {
        // TODO: Implement RPC call to full nodes
        // This would:
        // 1. Query multiple full nodes for latest certificates
        // 2. Verify consistency across nodes
        // 3. Return verified certificates

        Err(Error::Network(
            "RPC implementation required for fetching certificates".to_string(),
        ))
    }

    /// Query object state from full nodes with proof
    ///
    /// This is a placeholder for actual RPC implementation.
    pub async fn query_object_with_proof(
        &self,
        _object_id: ObjectID,
    ) -> Result<(Object, StateProof)> {
        // TODO: Implement RPC call to full nodes
        // This would:
        // 1. Query full node for object and proof
        // 2. Track bandwidth usage
        // 3. Return object and proof for verification

        Err(Error::Network(
            "RPC implementation required for querying objects".to_string(),
        ))
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
}

/// RPC client for communicating with full nodes
///
/// This is a placeholder for the actual RPC implementation.
/// In a real implementation, this would use HTTP/WebSocket to
/// communicate with full node JSON-RPC endpoints.
pub struct FullNodeRpcClient {
    endpoint: String,
    timeout: Duration,
}

impl FullNodeRpcClient {
    /// Create a new RPC client
    pub fn new(endpoint: String, timeout_ms: u64) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Fetch the latest snapshot certificate
    pub async fn get_latest_certificate(&self) -> Result<SnapshotCertificate> {
        // TODO: Implement actual RPC call
        Err(Error::Network(format!(
            "RPC not implemented for endpoint: {}",
            self.endpoint
        )))
    }

    /// Fetch a specific snapshot certificate by sequence number
    pub async fn get_certificate(
        &self,
        _sequence: SnapshotSequenceNumber,
    ) -> Result<SnapshotCertificate> {
        // TODO: Implement actual RPC call
        Err(Error::Network(format!(
            "RPC not implemented for endpoint: {}",
            self.endpoint
        )))
    }

    /// Query object state with proof
    pub async fn get_object_with_proof(
        &self,
        _object_id: ObjectID,
    ) -> Result<(Object, StateProof)> {
        // TODO: Implement actual RPC call
        Err(Error::Network(format!(
            "RPC not implemented for endpoint: {}",
            self.endpoint
        )))
    }

    /// Check if the full node is reachable
    pub async fn health_check(&self) -> Result<bool> {
        // TODO: Implement actual health check
        Err(Error::Network(format!(
            "Health check not implemented for endpoint: {}",
            self.endpoint
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_tracker() {
        let mut tracker = BandwidthTracker::new(10_000);

        // Record usage within limit
        assert!(tracker.record_usage(5_000).is_ok());
        assert_eq!(tracker.bytes_used_today, 5_000);

        // Record more usage
        assert!(tracker.record_usage(4_000).is_ok());
        assert_eq!(tracker.bytes_used_today, 9_000);

        // Exceed limit
        assert!(tracker.record_usage(2_000).is_err());
        assert_eq!(tracker.bytes_used_today, 9_000); // Should not increase
    }

    #[test]
    fn test_bandwidth_stats() {
        let tracker = BandwidthTracker::new(10_000);
        let stats = tracker.usage_stats();

        assert_eq!(stats.bytes_used_today, 0);
        assert_eq!(stats.max_bytes_per_day, 10_000);
        assert_eq!(stats.percentage_used, 0.0);
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        assert!(!manager.is_running().await);

        let stats = manager.bandwidth_stats().await;
        assert_eq!(stats.bytes_used_today, 0);
    }

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();

        assert_eq!(config.sync_interval_secs, 60);
        assert_eq!(config.max_bandwidth_per_day, 10 * 1024 * 1024);
        assert_eq!(config.certificates_per_sync, 10);
    }

    #[test]
    fn test_rpc_client_creation() {
        let client = FullNodeRpcClient::new("http://localhost:9545".to_string(), 5000);

        assert_eq!(client.endpoint, "http://localhost:9545");
        assert_eq!(client.timeout, Duration::from_millis(5000));
    }
}
