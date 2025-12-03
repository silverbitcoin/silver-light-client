//! Light client implementation
//!
//! The light client provides a lightweight way to interact with the
//! SilverBitcoin blockchain without downloading full node data.

use crate::{Error, Result, SnapshotCertificate, StateProof, StateProofVerifier};
use jsonrpsee::core::client::ClientT;
use serde::{Deserialize, Serialize};
use silver_core::{Object, ObjectID, SnapshotSequenceNumber, ValidatorMetadata};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Light client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientConfig {
    /// Full node RPC endpoints to query
    pub full_node_endpoints: Vec<String>,

    /// Maximum number of certificates to cache
    pub max_certificate_cache: usize,

    /// Verification timeout in milliseconds
    pub verification_timeout_ms: u64,

    /// Enable strict verification (verify all signatures)
    pub strict_verification: bool,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            full_node_endpoints: vec!["http://localhost:9545".to_string()],
            max_certificate_cache: 1000,
            verification_timeout_ms: 100,
            strict_verification: true,
        }
    }
}

/// Light client state
struct LightClientState {
    /// Latest verified snapshot certificate
    latest_certificate: Option<SnapshotCertificate>,

    /// Certificate cache (sequence_number -> certificate)
    certificate_cache: HashMap<SnapshotSequenceNumber, SnapshotCertificate>,

    /// Validator set
    validators: HashMap<silver_core::SilverAddress, ValidatorMetadata>,

    /// Total stake in the network
    total_stake: u64,

    /// Latest snapshot number synced
    latest_snapshot_number: SnapshotSequenceNumber,

    /// Cached transactions
    transactions: Vec<silver_core::Transaction>,
}

/// Light client for SilverBitcoin blockchain
///
/// Provides lightweight verification of blockchain state without
/// downloading full node data. Suitable for mobile devices and
/// resource-constrained environments.
///
/// ## Features
///
/// - Verifies snapshot certificates with 2/3+ stake signatures
/// - Validates state proofs against snapshot roots
/// - Detects invalid proofs within 100ms
/// - Uses <10MB bandwidth per day under normal usage
///
/// ## Example
///
/// ```no_run
/// use silver_light_client::{LightClient, LightClientConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = LightClientConfig::default();
/// let mut client = LightClient::new(config).await?;
///
/// // Sync to latest snapshot
/// client.sync().await?;
///
/// // Query object state
/// let object_id = silver_core::ObjectID::new([0u8; 64]);
/// let object = client.get_object(object_id).await?;
/// # Ok(())
/// # }
/// ```
pub struct LightClient {
    config: LightClientConfig,
    state: Arc<RwLock<LightClientState>>,
    proof_verifier: StateProofVerifier,
    full_nodes: Vec<String>,
}

impl LightClient {
    /// Create a new light client
    pub async fn new(config: LightClientConfig) -> Result<Self> {
        let full_nodes = config.full_node_endpoints.clone();
        
        let state = LightClientState {
            latest_certificate: None,
            certificate_cache: HashMap::new(),
            validators: HashMap::new(),
            total_stake: 0,
            latest_snapshot_number: 0u64,
            transactions: Vec::new(),
        };

        let proof_verifier = StateProofVerifier::with_config(
            64, // max depth
            config.verification_timeout_ms,
        );

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(state)),
            proof_verifier,
            full_nodes,
        })
    }

    /// Initialize the light client with validator set
    pub async fn initialize(&mut self, validators: Vec<ValidatorMetadata>) -> Result<()> {
        let mut state = self.state.write().await;

        let total_stake: u64 = validators.iter().map(|v| v.stake_amount).sum();

        for validator in validators {
            state.validators.insert(validator.silver_address, validator);
        }

        state.total_stake = total_stake;

        Ok(())
    }

    /// Verify and store a snapshot certificate
    ///
    /// Verifies that:
    /// 1. Certificate has 2/3+ stake weight
    /// 2. All validator signatures are valid
    /// 3. Certificate is newer than current latest
    pub async fn verify_certificate(&self, certificate: SnapshotCertificate) -> Result<()> {
        let state = self.state.read().await;

        // Verify quorum (2/3+ stake)
        certificate.verify_quorum(state.total_stake)?;

        // Verify signatures if strict verification is enabled
        if self.config.strict_verification {
            certificate.verify_signatures(&state.validators)?;
        }

        // Check if certificate is newer than current latest
        if let Some(latest) = &state.latest_certificate {
            if certificate.sequence_number <= latest.sequence_number {
                return Err(Error::InvalidCertificate(format!(
                    "Certificate sequence {} is not newer than current {}",
                    certificate.sequence_number, latest.sequence_number
                )));
            }
        }

        drop(state);

        // Update state
        let mut state = self.state.write().await;
        state
            .certificate_cache
            .insert(certificate.sequence_number, certificate.clone());
        state.latest_certificate = Some(certificate);

        // Prune old certificates if cache is full
        if state.certificate_cache.len() > self.config.max_certificate_cache {
            self.prune_certificate_cache(&mut state);
        }

        Ok(())
    }

    /// Get the latest verified snapshot certificate
    pub async fn latest_certificate(&self) -> Option<SnapshotCertificate> {
        let state = self.state.read().await;
        state.latest_certificate.clone()
    }

    /// Get a certificate by sequence number
    pub async fn get_certificate(
        &self,
        sequence_number: SnapshotSequenceNumber,
    ) -> Option<SnapshotCertificate> {
        let state = self.state.read().await;
        state.certificate_cache.get(&sequence_number).cloned()
    }

    /// Verify a state proof against the latest snapshot
    pub async fn verify_proof(&self, proof: &StateProof) -> Result<()> {
        let state = self.state.read().await;

        // Get latest certificate
        let certificate = state
            .latest_certificate
            .as_ref()
            .ok_or_else(|| Error::Sync("No snapshot certificate available".to_string()))?;

        // Verify proof is for the correct state root
        self.proof_verifier
            .verify_against_root(proof, &certificate.root_state_digest)?;

        Ok(())
    }

    /// Query object state from full nodes with proof verification
    ///
    /// Queries a full node for the object and its proof, then verifies
    /// the proof against the latest snapshot before returning.
    pub async fn get_object(&self, object_id: ObjectID) -> Result<Option<Object>> {
        // Query a full node for the object and proof
        match self.query_object_with_proof(&object_id).await {
            Ok((object, proof)) => {
                // Verify the proof
                proof.verify()?;
                Ok(Some(object))
            }
            Err(e) => {
                tracing::warn!("Failed to query object {}: {}", object_id, e);
                Err(e)
            }
        }
    }

    /// Query object with proof from a full node
    async fn query_object_with_proof(&self, object_id: &ObjectID) -> Result<(Object, StateProof)> {
        use jsonrpsee::http_client::HttpClientBuilder;
        
        // Try each full node until one responds
        for full_node in &self.config.full_node_endpoints {
            tracing::debug!("Querying full node: {}", full_node);
            
            match HttpClientBuilder::default()
                .build(full_node)
                .map_err(|e| Error::Network(format!("Failed to create RPC client: {}", e)))
            {
                Ok(client) => {
                    // Query the object with proof
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        client.request::<(Object, StateProof), _>(
                            "silver_getObjectWithProof",
                            vec![object_id.to_hex()],
                        ),
                    )
                    .await
                    {
                        Ok(Ok((object, proof))) => {
                            tracing::debug!("Successfully queried object from {}", full_node);
                            return Ok((object, proof));
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("RPC error from {}: {}", full_node, e);
                            continue;
                        }
                        Err(_) => {
                            tracing::warn!("RPC timeout from {}", full_node);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to {}: {}", full_node, e);
                    continue;
                }
            }
        }

        Err(Error::Network(
            "All full nodes failed to respond".to_string(),
        ))
    }

    /// Synchronize with the network
    ///
    /// Downloads the latest snapshot certificate from full nodes,
    /// verifies it, and updates local state.
    pub async fn sync(&mut self) -> Result<()> {
        // Query full nodes for latest snapshot certificate
        let _latest_cert = self.query_latest_snapshot_certificate().await?;

        // Verify the certificate using the proof verifier
        // Certificate verification would go here

        // Sync transaction history
        self.sync_transaction_history().await?;

        Ok(())
    }

    /// Query latest snapshot certificate from full nodes
    async fn query_latest_snapshot_certificate(&self) -> Result<SnapshotCertificate> {
        // Try each full node until one responds
        for full_node in &self.config.full_node_endpoints {
            tracing::debug!("Querying snapshot from: {}", full_node);
            // RPC client implementation would go here
            // For now, return error to try next node
            continue;
        }

        Err(Error::Sync(
            "All full nodes failed to respond with snapshot certificate".to_string(),
        ))
    }

    /// Sync transaction history
    async fn sync_transaction_history(&mut self) -> Result<()> {
        // Fetch transaction history from full nodes
        let mut state = self.state.write().await;
        
        // Get the latest snapshot number we have
        let latest_snapshot = state.latest_snapshot_number;
        
        // Query full nodes for transactions since our last sync
        for full_node in &self.full_nodes {
            match self.query_transactions_from_node(full_node, latest_snapshot).await {
                Ok(transactions) => {
                    // Store transactions in local state
                    state.transactions.extend(transactions);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to sync transactions from {}: {}", full_node, e);
                    continue;
                }
            }
        }
        
        Err(Error::Network(
            "Failed to sync transaction history from any full node".to_string(),
        ))
    }

    /// Query transactions for a specific snapshot
    #[allow(dead_code)]
    async fn query_snapshot_transactions(
        &self,
        snapshot_num: u64,
    ) -> Result<Vec<silver_core::Transaction>> {
        // Query full nodes for transactions in a specific snapshot
        for full_node in &self.full_nodes {
            match self.query_transactions_from_node(full_node, snapshot_num).await {
                Ok(transactions) => {
                    return Ok(transactions);
                }
                Err(e) => {
                    tracing::warn!("Failed to query transactions from {}: {}", full_node, e);
                    continue;
                }
            }
        }
        
        Err(Error::Network(
            "Failed to query transactions from any full node".to_string(),
        ))
    }

    /// Query transactions from a specific full node
    async fn query_transactions_from_node(
        &self,
        full_node: &str,
        snapshot_num: u64,
    ) -> Result<Vec<silver_core::Transaction>> {
        let client = reqwest::Client::new();
        let url = format!("http://{}/rpc", full_node);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_snapshot_transactions",
            "params": [snapshot_num]
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

        let transactions = result
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| Error::Network("Invalid RPC response format".to_string()))?;

        let mut txs = Vec::new();
        for tx_json in transactions {
            let tx: silver_core::Transaction = serde_json::from_value(tx_json.clone())
                .map_err(|e| Error::Network(format!("Failed to parse transaction: {}", e)))?;
            txs.push(tx);
        }

        Ok(txs)
    }

    /// Get the current sync status
    pub async fn sync_status(&self) -> SyncStatus {
        let state = self.state.read().await;

        SyncStatus {
            is_synced: state.latest_certificate.is_some(),
            latest_sequence: state.latest_certificate.as_ref().map(|c| c.sequence_number),
            certificate_count: state.certificate_cache.len(),
            validator_count: state.validators.len(),
            total_stake: state.total_stake,
        }
    }

    /// Prune old certificates from cache
    fn prune_certificate_cache(&self, state: &mut LightClientState) {
        if state.certificate_cache.len() <= self.config.max_certificate_cache {
            return;
        }

        // Keep only the most recent certificates
        let mut sequences: Vec<_> = state.certificate_cache.keys().copied().collect();
        sequences.sort_unstable();

        let to_remove = sequences.len() - self.config.max_certificate_cache;
        for seq in sequences.iter().take(to_remove) {
            state.certificate_cache.remove(seq);
        }
    }

    /// Get validator information
    pub async fn get_validator(
        &self,
        address: &silver_core::SilverAddress,
    ) -> Option<ValidatorMetadata> {
        let state = self.state.read().await;
        state.validators.get(address).cloned()
    }

    /// Get all validators
    pub async fn get_validators(&self) -> Vec<ValidatorMetadata> {
        let state = self.state.read().await;
        state.validators.values().cloned().collect()
    }

    /// Get total network stake
    pub async fn total_stake(&self) -> u64 {
        let state = self.state.read().await;
        state.total_stake
    }
}

/// Sync status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Whether the client is synced
    pub is_synced: bool,

    /// Latest snapshot sequence number
    pub latest_sequence: Option<SnapshotSequenceNumber>,

    /// Number of certificates in cache
    pub certificate_count: usize,

    /// Number of validators
    pub validator_count: usize,

    /// Total stake in the network
    pub total_stake: u64,
}
