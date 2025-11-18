//! Snapshot certificate generation and verification
//!
//! This module implements compact snapshot certificates that contain
//! validator signatures and state root hashes, enabling light clients
//! to verify blockchain state without downloading full node data.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use silver_core::{
    Snapshot, SnapshotDigest, SnapshotSequenceNumber, StateDigest, ValidatorMetadata,
    ValidatorSignature,
};
use std::collections::HashMap;

/// Compact snapshot certificate for light client verification
///
/// Contains only the essential information needed to verify a snapshot:
/// - Snapshot metadata (sequence number, timestamp, state root)
/// - Validator signatures proving 2/3+ stake agreement
/// - Stake weight information for verification
///
/// This is much smaller than a full snapshot as it excludes the full
/// transaction list, making it suitable for bandwidth-constrained clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCertificate {
    /// Snapshot sequence number
    pub sequence_number: SnapshotSequenceNumber,

    /// Unix timestamp (milliseconds)
    pub timestamp: u64,

    /// Digest of previous snapshot
    pub previous_digest: SnapshotDigest,

    /// Root hash of the state tree
    pub root_state_digest: StateDigest,

    /// Number of transactions in this snapshot
    pub transaction_count: usize,

    /// Cycle ID (validator set epoch)
    pub cycle: u64,

    /// Validator signatures on this snapshot
    pub validator_signatures: Vec<ValidatorSignature>,

    /// Total stake weight of signers
    pub stake_weight: u64,

    /// Snapshot digest (hash of snapshot)
    pub snapshot_digest: SnapshotDigest,

    /// Certificate creation timestamp
    pub certificate_timestamp: u64,
}

impl SnapshotCertificate {
    /// Create a new snapshot certificate from a full snapshot
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        Self {
            sequence_number: snapshot.sequence_number,
            timestamp: snapshot.timestamp,
            previous_digest: snapshot.previous_digest,
            root_state_digest: snapshot.root_state_digest,
            transaction_count: snapshot.transactions.len(),
            cycle: snapshot.cycle,
            validator_signatures: snapshot.validator_signatures.clone(),
            stake_weight: snapshot.stake_weight,
            snapshot_digest: snapshot.digest,
            certificate_timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Verify the certificate has sufficient stake weight (2/3+ quorum)
    pub fn verify_quorum(&self, total_stake: u64) -> Result<()> {
        // Require 2/3+ stake weight
        let required_stake = (total_stake * 2) / 3 + 1;

        if self.stake_weight < required_stake {
            return Err(Error::InsufficientStake {
                current: self.stake_weight,
                required: required_stake,
            });
        }

        Ok(())
    }

    /// Verify validator signatures on this certificate
    pub fn verify_signatures(
        &self,
        validators: &HashMap<silver_core::SilverAddress, ValidatorMetadata>,
    ) -> Result<()> {
        if self.validator_signatures.is_empty() {
            return Err(Error::InvalidCertificate(
                "Certificate has no signatures".to_string(),
            ));
        }

        let mut verified_stake = 0u64;

        for sig in &self.validator_signatures {
            // Get validator metadata
            let validator = validators
                .get(&sig.validator.address)
                .ok_or_else(|| {
                    Error::InvalidCertificate(format!(
                        "Unknown validator: {}",
                        sig.validator.address
                    ))
                })?;

            // Verify signature
            let message = self.signing_message();
            
            // Create appropriate verifier based on signature scheme
            let verifier: Box<dyn silver_crypto::SignatureVerifier> = match sig.signature.scheme {
                silver_core::SignatureScheme::SphincsPlus => {
                    Box::new(silver_crypto::SphincsPlus)
                }
                silver_core::SignatureScheme::Dilithium3 => {
                    Box::new(silver_crypto::Dilithium3)
                }
                silver_core::SignatureScheme::Secp512r1 => {
                    Box::new(silver_crypto::Secp512r1)
                }
                silver_core::SignatureScheme::Hybrid => {
                    Box::new(silver_crypto::HybridSignature)
                }
            };
            
            if let Err(_) = verifier.verify(&message, &sig.signature, &validator.protocol_pubkey) {
                return Err(Error::InvalidCertificate(format!(
                    "Invalid signature from validator: {}",
                    sig.validator.address
                )));
            }

            verified_stake += validator.stake_amount;
        }

        // Verify stake weight matches
        if verified_stake != self.stake_weight {
            return Err(Error::InvalidCertificate(format!(
                "Stake weight mismatch: claimed {}, verified {}",
                self.stake_weight, verified_stake
            )));
        }

        Ok(())
    }

    /// Get the message that validators sign
    fn signing_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&self.sequence_number.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        message.extend_from_slice(self.previous_digest.as_bytes());
        message.extend_from_slice(self.root_state_digest.as_bytes());
        message.extend_from_slice(&self.cycle.to_le_bytes());
        message.extend_from_slice(self.snapshot_digest.as_bytes());
        message
    }

    /// Get the size of this certificate in bytes
    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self).map(|b| b.len()).unwrap_or(0)
    }

    /// Check if this is the genesis certificate
    pub fn is_genesis(&self) -> bool {
        self.sequence_number == 0
    }

    /// Get the age of this certificate in milliseconds
    pub fn age_ms(&self) -> u64 {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        now.saturating_sub(self.certificate_timestamp)
    }
}

/// Builder for creating snapshot certificates
pub struct SnapshotCertificateBuilder {
    snapshot: Option<Snapshot>,
    validators: HashMap<silver_core::SilverAddress, ValidatorMetadata>,
}

impl SnapshotCertificateBuilder {
    /// Create a new certificate builder
    pub fn new() -> Self {
        Self {
            snapshot: None,
            validators: HashMap::new(),
        }
    }

    /// Set the snapshot to create a certificate for
    pub fn snapshot(mut self, snapshot: Snapshot) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    /// Add validator metadata for signature verification
    pub fn add_validator(mut self, validator: ValidatorMetadata) -> Self {
        self.validators
            .insert(validator.silver_address, validator);
        self
    }

    /// Add multiple validators
    pub fn add_validators(mut self, validators: Vec<ValidatorMetadata>) -> Self {
        for validator in validators {
            self.validators
                .insert(validator.silver_address, validator);
        }
        self
    }

    /// Build the snapshot certificate
    pub fn build(self) -> Result<SnapshotCertificate> {
        let snapshot = self
            .snapshot
            .ok_or_else(|| Error::InvalidConfig("No snapshot provided".to_string()))?;

        // Create certificate from snapshot
        let certificate = SnapshotCertificate::from_snapshot(&snapshot);

        // Verify the certificate has valid signatures
        certificate.verify_signatures(&self.validators)?;

        // Calculate total stake
        let total_stake: u64 = self.validators.values().map(|v| v.stake_amount).sum();

        // Verify quorum
        certificate.verify_quorum(total_stake)?;

        Ok(certificate)
    }
}

impl Default for SnapshotCertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_core::{PublicKey, Signature, SignatureScheme, SilverAddress, ValidatorID, Snapshot};

    fn create_test_validator(stake: u64) -> ValidatorMetadata {
        let addr = SilverAddress::new([1u8; 64]);
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

    fn create_test_snapshot() -> Snapshot {
        Snapshot::new(
            1,
            1000,
            SnapshotDigest::new([0u8; 64]),
            StateDigest::new([1u8; 64]),
            vec![],
            0,
            vec![],
            1000,
        )
    }

    #[test]
    fn test_certificate_from_snapshot() {
        let snapshot = create_test_snapshot();
        let cert = SnapshotCertificate::from_snapshot(&snapshot);

        assert_eq!(cert.sequence_number, snapshot.sequence_number);
        assert_eq!(cert.timestamp, snapshot.timestamp);
        assert_eq!(cert.root_state_digest, snapshot.root_state_digest);
        assert_eq!(cert.transaction_count, snapshot.transactions.len());
    }

    #[test]
    fn test_certificate_quorum_verification() {
        let snapshot = create_test_snapshot();
        let cert = SnapshotCertificate::from_snapshot(&snapshot);

        // Test with sufficient stake (2/3+)
        assert!(cert.verify_quorum(1000).is_ok());

        // Test with insufficient stake
        assert!(cert.verify_quorum(2000).is_err());
    }

    #[test]
    fn test_certificate_size() {
        let snapshot = create_test_snapshot();
        let cert = SnapshotCertificate::from_snapshot(&snapshot);

        let size = cert.size_bytes();
        assert!(size > 0);
        assert!(size < 10_000); // Should be compact (< 10KB)
    }

    #[test]
    fn test_certificate_is_genesis() {
        let mut snapshot = create_test_snapshot();
        snapshot.sequence_number = 0;
        let cert = SnapshotCertificate::from_snapshot(&snapshot);

        assert!(cert.is_genesis());

        snapshot.sequence_number = 1;
        let cert = SnapshotCertificate::from_snapshot(&snapshot);
        assert!(!cert.is_genesis());
    }
}
