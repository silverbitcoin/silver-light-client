//! Light client implementation
//!
//! The light client provides a lightweight way to interact with the
//! SilverBitcoin blockchain without downloading full node data.

use crate::{Error, Result, SnapshotCertificate, StateProof, StateProofVerifier};
use serde::{Deserialize, Serialize};
use silver_core::{
    Object, ObjectID, SnapshotSequenceNumber, ValidatorMetadata,
};
use std::collections::HashMap;
use std::sync::Arc;
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
}

impl LightClient {
    /// Create a new light client
    pub async fn new(config: LightClientConfig) -> Result<Self> {
        let state = LightClientState {
            latest_certificate: None,
            certificate_cache: HashMap::new(),
            validators: HashMap::new(),
            total_stake: 0,
        };

        let proof_verifier = StateProofVerifier::with_config(
            64, // max depth
            config.verification_timeout_ms,
        );

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(state)),
            proof_verifier,
        })
    }

    /// Initialize the light client with validator set
    pub async fn initialize(&mut self, validators: Vec<ValidatorMetadata>) -> Result<()> {
        let mut state = self.state.write().await;

        let total_stake: u64 = validators.iter().map(|v| v.stake_amount).sum();

        for validator in validators {
            state
                .validators
                .insert(validator.silver_address, validator);
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
    pub async fn verify_certificate(
        &self,
        certificate: SnapshotCertificate,
    ) -> Result<()> {
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
        let (object, proof) = self.query_object_with_proof(&object_id).await?;

        if let Some(obj) = &object {
            // Verify the proof against the latest snapshot
            self.verifier.verify_object_proof(
                &obj,
                &proof,
                &self.latest_snapshot,
            )?;
        }

        Ok(object)
    }

    /// Query object with proof from a full node
    async fn query_object_with_proof(
        &self,
        object_id: &ObjectID,
    ) -> Result<(Option<Object>, ObjectProof)> {
        // Try each full node until one responds
        for full_node in &self.full_nodes {
            match self.rpc_client.get_object_with_proof(full_node, object_id).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!("Failed to query {}: {}", full_node, e);
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
        let latest_cert = self.query_latest_snapshot_certificate().await?;

        // Verify the certificate
        self.verifier.verify_snapshot_certificate(&latest_cert)?;

        // Update local state
        self.latest_snapshot = latest_cert.snapshot.clone();
        self.latest_certificate = Some(latest_cert);

        // Sync transaction history
        self.sync_transaction_history().await?;

        Ok(())
    }

    /// Query latest snapshot certificate from full nodes
    async fn query_latest_snapshot_certificate(&self) -> Result<SnapshotCertificate> {
        // Try each full node until one responds
        for full_node in &self.full_nodes {
            match self.rpc_client.get_latest_snapshot_certificate(full_node).await {
                Ok(cert) => return Ok(cert),
                Err(e) => {
                    tracing::warn!("Failed to query snapshot from {}: {}", full_node, e);
                    continue;
                }
            }
        }

        Err(Error::Sync(
            "All full nodes failed to respond with snapshot certificate".to_string(),
        ))
    }

    /// Sync transaction history
    async fn sync_transaction_history(&mut self) -> Result<()> {
        let start_snapshot = self.last_synced_snapshot;
        let end_snapshot = self.latest_snapshot.sequence_number;

        for snapshot_num in start_snapshot..=end_snapshot {
            let transactions = self.query_snapshot_transactions(snapshot_num).await?;
            self.transaction_cache.extend(transactions);
        }

        self.last_synced_snapshot = end_snapshot;
        Ok(())
    }

    /// Query transactions for a specific snapshot
    async fn query_snapshot_transactions(&self, snapshot_num: u64) -> Result<Vec<Transaction>> {
        for full_node in &self.full_nodes {
            match self.rpc_client.get_snapshot_transactions(full_node, snapshot_num).await {
                Ok(txs) => return Ok(txs),
                Err(e) => {
                    tracing::warn!("Failed to query transactions from {}: {}", full_node, e);
                    continue;
                }
            }
        }

        Err(Error::Sync(
            "All full nodes failed to respond with transactions".to_string(),
        ))
    }

    /// Get the current sync status
    pub async fn sync_status(&self) -> SyncStatus {
        let state = self.state.read().await;

        SyncStatus {
            is_synced: state.latest_certificate.is_some(),
            latest_sequence: state
                .latest_certificate
                .as_ref()
                .map(|c| c.sequence_number),
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

#[cfg(test)]
mod tests {
    use super::*;
    use silver_core::{PublicKey, SignatureScheme, SilverAddress, Snapshot, StateDigest};

    fn create_test_validator(stake: u64) -> ValidatorMetadata {
        // Use stake amount as part of address to make each validator unique
        let mut addr_bytes = [0u8; 64];
        addr_bytes[0..8].copy_from_slice(&stake.to_le_bytes());
        let addr = SilverAddress::new(addr_bytes);
        
        let pubkey = PublicKey {
            scheme: SignatureScheme::Dilithium3,
            bytes: vec![0u8; 100],
        };

        ValidatorMetadata::new(
            addr,
            pubkey.clone(),
            pubkey.clone(),
            pubkey,
            stake,
            "127.0.0.1:9000".to_string(),
            "127.0.0.1:9001".to_string(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_light_client_creation() {
        let config = LightClientConfig::default();
        let client = LightClient::new(config).await.unwrap();

        let status = client.sync_status().await;
        assert!(!status.is_synced);
        assert_eq!(status.validator_count, 0);
    }

    #[tokio::test]
    async fn test_light_client_initialization() {
        let config = LightClientConfig::default();
        let mut client = LightClient::new(config).await.unwrap();

        let validators = vec![
            create_test_validator(1_000_000),
            create_test_validator(2_000_000),
        ];

        client.initialize(validators).await.unwrap();

        let status = client.sync_status().await;
        assert_eq!(status.validator_count, 2);
        assert_eq!(status.total_stake, 3_000_000);
    }

    #[tokio::test]
    async fn test_certificate_verification() {
        let config = LightClientConfig {
            strict_verification: false, // Disable signature verification for test
            ..Default::default()
        };
        let mut client = LightClient::new(config).await.unwrap();

        let validators = vec![create_test_validator(1_000_000)];
        client.initialize(validators).await.unwrap();

        // Create a test certificate
        let snapshot = Snapshot::new(
            1,
            1000,
            silver_core::SnapshotDigest::new([0u8; 64]),
            StateDigest::new([1u8; 64]),
            vec![],
            0,
            vec![],
            1_000_000,
        );

        let certificate = SnapshotCertificate::from_snapshot(&snapshot);

        // Verify certificate
        let result = client.verify_certificate(certificate).await;
        assert!(result.is_ok());

        // Check latest certificate
        let latest = client.latest_certificate().await;
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().sequence_number, 1);
    }
}
