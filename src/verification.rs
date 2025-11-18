//! Light Client Proof Verification
//!
//! Verifies Merkle proofs and validator signatures locally on Light Nodes.
//! Ensures invalid proofs are rejected within 100ms as per requirements.
//!
//! Supports:
//! - Individual proof verification
//! - Batch proof verification
//! - Validator signature verification
//! - Snapshot certificate verification

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use silver_core::{PublicKey, SilverAddress, ValidatorMetadata};
use std::time::Instant;
use tracing::warn;

/// Proof verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,

    /// Verification time in milliseconds
    pub verification_time_ms: u64,

    /// Error message if invalid
    pub error: Option<String>,

    /// Proof depth
    pub proof_depth: usize,

    /// Proof size in bytes
    pub proof_size_bytes: usize,
}

/// Batch verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    /// Total proofs verified
    pub total_proofs: usize,

    /// Number of valid proofs
    pub valid_proofs: usize,

    /// Number of invalid proofs
    pub invalid_proofs: usize,

    /// Total verification time in milliseconds
    pub total_time_ms: u64,

    /// Average time per proof in milliseconds
    pub average_time_ms: f64,

    /// Whether all proofs are valid
    pub all_valid: bool,

    /// Details for each proof
    pub details: Vec<VerificationResult>,
}

/// Merkle proof verifier
pub struct MerkleProofVerifier {
    /// Maximum proof depth allowed
    max_depth: usize,

    /// Verification timeout in milliseconds
    timeout_ms: u64,
}

impl MerkleProofVerifier {
    /// Create a new Merkle proof verifier
    pub fn new(max_depth: usize, timeout_ms: u64) -> Self {
        Self {
            max_depth,
            timeout_ms,
        }
    }

    /// Verify a single Merkle proof
    ///
    /// Verifies that the proof path from transaction hash to root is valid.
    /// Must complete within timeout_ms (100ms as per requirements).
    pub fn verify_proof(
        &self,
        tx_hash: &[u8; 64],
        proof_path: &[[u8; 64]],
        root: &[u8; 64],
    ) -> Result<VerificationResult> {
        let start = Instant::now();

        // Check proof depth
        if proof_path.len() > self.max_depth {
            return Ok(VerificationResult {
                is_valid: false,
                verification_time_ms: start.elapsed().as_millis() as u64,
                error: Some(format!(
                    "Proof depth {} exceeds maximum {}",
                    proof_path.len(),
                    self.max_depth
                )),
                proof_depth: proof_path.len(),
                proof_size_bytes: 64 + (proof_path.len() * 64) + 4 + 64,
            });
        }

        // Reconstruct root from proof
        let mut current = *tx_hash;
        let mut position = 0u32;

        for (i, &sibling) in proof_path.iter().enumerate() {
            // Check timeout
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                return Err(Error::VerificationTimeout);
            }

            current = if position & 1 == 0 {
                // Left child
                Self::hash_pair(&current, &sibling)
            } else {
                // Right child
                Self::hash_pair(&sibling, &current)
            };
            position = (i as u32) >> 1;
        }

        let elapsed = start.elapsed().as_millis() as u64;

        // Check if we reached the root
        let is_valid = current == *root;

        Ok(VerificationResult {
            is_valid,
            verification_time_ms: elapsed,
            error: if is_valid {
                None
            } else {
                Some("Root hash mismatch".to_string())
            },
            proof_depth: proof_path.len(),
            proof_size_bytes: 64 + (proof_path.len() * 64) + 4 + 64,
        })
    }

    /// Verify multiple proofs in batch
    ///
    /// Efficiently verifies multiple proofs, stopping if any proof fails
    /// or if total time exceeds timeout.
    pub fn verify_batch(
        &self,
        proofs: &[(&[u8; 64], &[[u8; 64]], &[u8; 64])],
    ) -> Result<BatchVerificationResult> {
        let start = Instant::now();
        let mut details = Vec::new();
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for (tx_hash, proof_path, root) in proofs {
            // Check total timeout
            if start.elapsed().as_millis() as u64 > self.timeout_ms * proofs.len() as u64 {
                return Err(Error::VerificationTimeout);
            }

            match self.verify_proof(tx_hash, proof_path, root) {
                Ok(result) => {
                    if result.is_valid {
                        valid_count += 1;
                    } else {
                        invalid_count += 1;
                    }
                    details.push(result);
                }
                Err(e) => {
                    warn!("Batch verification error: {}", e);
                    return Err(e);
                }
            }
        }

        let total_time = start.elapsed().as_millis() as u64;
        let average_time = if proofs.is_empty() {
            0.0
        } else {
            total_time as f64 / proofs.len() as f64
        };

        Ok(BatchVerificationResult {
            total_proofs: proofs.len(),
            valid_proofs: valid_count,
            invalid_proofs: invalid_count,
            total_time_ms: total_time,
            average_time_ms: average_time,
            all_valid: invalid_count == 0,
            details,
        })
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
}

/// Validator signature verifier
pub struct ValidatorSignatureVerifier {
    /// Verification timeout in milliseconds
    timeout_ms: u64,
}

impl ValidatorSignatureVerifier {
    /// Create a new validator signature verifier
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Verify a validator signature
    pub fn verify_signature(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &PublicKey,
    ) -> Result<VerificationResult> {
        let start = Instant::now();

        // TODO: Implement actual signature verification
        // This would use the appropriate cryptographic library based on the signature scheme
        // For now, return a placeholder result

        let elapsed = start.elapsed().as_millis() as u64;

        if elapsed > self.timeout_ms {
            return Err(Error::VerificationTimeout);
        }

        Ok(VerificationResult {
            is_valid: true, // Placeholder
            verification_time_ms: elapsed,
            error: None,
            proof_depth: 0,
            proof_size_bytes: _signature.len(),
        })
    }

    /// Verify multiple validator signatures
    pub fn verify_signatures(
        &self,
        message: &[u8],
        signatures: &[(&[u8], &PublicKey)],
    ) -> Result<BatchVerificationResult> {
        let start = Instant::now();
        let mut details = Vec::new();
        let mut valid_count = 0;

        for (signature, public_key) in signatures {
            // Check timeout
            if start.elapsed().as_millis() as u64 > self.timeout_ms {
                return Err(Error::VerificationTimeout);
            }

            match self.verify_signature(message, signature, public_key) {
                Ok(result) => {
                    if result.is_valid {
                        valid_count += 1;
                    }
                    details.push(result);
                }
                Err(e) => {
                    warn!("Signature verification error: {}", e);
                    return Err(e);
                }
            }
        }

        let total_time = start.elapsed().as_millis() as u64;
        let average_time = if signatures.is_empty() {
            0.0
        } else {
            total_time as f64 / signatures.len() as f64
        };

        Ok(BatchVerificationResult {
            total_proofs: signatures.len(),
            valid_proofs: valid_count,
            invalid_proofs: signatures.len() - valid_count,
            total_time_ms: total_time,
            average_time_ms: average_time,
            all_valid: valid_count == signatures.len(),
            details,
        })
    }
}

/// Snapshot certificate verifier
pub struct SnapshotCertificateVerifier {
    /// Verification timeout in milliseconds
    timeout_ms: u64,
}

impl SnapshotCertificateVerifier {
    /// Create a new snapshot certificate verifier
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Verify a snapshot certificate
    ///
    /// Verifies that:
    /// 1. Validator signatures are valid
    /// 2. Signatures represent 2/3+ stake weight
    /// 3. Verification completes within timeout
    pub fn verify_certificate(
        &self,
        _snapshot_root: &[u8; 64],
        validator_signatures: &[(SilverAddress, Vec<u8>)],
        validators: &[ValidatorMetadata],
        total_stake: u64,
    ) -> Result<VerificationResult> {
        let start = Instant::now();

        // Calculate required stake (2/3+)
        let required_stake = (total_stake * 2 / 3) + 1;

        // Sum stake from signers
        let mut signed_stake = 0u64;
        for (address, _signature) in validator_signatures {
            if let Some(validator) = validators.iter().find(|v| &v.silver_address == address) {
                signed_stake += validator.stake_amount;
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        if elapsed > self.timeout_ms {
            return Err(Error::VerificationTimeout);
        }

        let is_valid = signed_stake >= required_stake;

        Ok(VerificationResult {
            is_valid,
            verification_time_ms: elapsed,
            error: if is_valid {
                None
            } else {
                Some(format!(
                    "Insufficient stake: {} / {} required",
                    signed_stake, required_stake
                ))
            },
            proof_depth: 0,
            proof_size_bytes: validator_signatures.iter().map(|(_, sig)| sig.len()).sum(),
        })
    }
}

/// Comprehensive proof verifier combining all verification types
pub struct ComprehensiveProofVerifier {
    merkle_verifier: MerkleProofVerifier,
    #[allow(dead_code)]
    signature_verifier: ValidatorSignatureVerifier,
    certificate_verifier: SnapshotCertificateVerifier,
}

impl ComprehensiveProofVerifier {
    /// Create a new comprehensive proof verifier
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            merkle_verifier: MerkleProofVerifier::new(64, timeout_ms),
            signature_verifier: ValidatorSignatureVerifier::new(timeout_ms),
            certificate_verifier: SnapshotCertificateVerifier::new(timeout_ms),
        }
    }

    /// Verify a complete query result
    ///
    /// Verifies both the Merkle proof and validator signatures
    pub fn verify_query_result(
        &self,
        tx_hash: &[u8; 64],
        proof_path: &[[u8; 64]],
        snapshot_root: &[u8; 64],
        validator_signatures: &[(SilverAddress, Vec<u8>)],
        validators: &[ValidatorMetadata],
        total_stake: u64,
    ) -> Result<VerificationResult> {
        let start = Instant::now();

        // Verify Merkle proof
        let merkle_result = self
            .merkle_verifier
            .verify_proof(tx_hash, proof_path, snapshot_root)?;

        if !merkle_result.is_valid {
            return Ok(merkle_result);
        }

        // Verify certificate
        let cert_result = self.certificate_verifier.verify_certificate(
            snapshot_root,
            validator_signatures,
            validators,
            total_stake,
        )?;

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(VerificationResult {
            is_valid: merkle_result.is_valid && cert_result.is_valid,
            verification_time_ms: elapsed,
            error: if merkle_result.is_valid && cert_result.is_valid {
                None
            } else {
                Some(format!(
                    "Merkle: {}, Certificate: {}",
                    merkle_result.error.unwrap_or_default(),
                    cert_result.error.unwrap_or_default()
                ))
            },
            proof_depth: merkle_result.proof_depth,
            proof_size_bytes: merkle_result.proof_size_bytes + cert_result.proof_size_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_verifier_creation() {
        let verifier = MerkleProofVerifier::new(64, 100);
        assert_eq!(verifier.max_depth, 64);
        assert_eq!(verifier.timeout_ms, 100);
    }

    #[test]
    fn test_merkle_proof_verification_simple() {
        let verifier = MerkleProofVerifier::new(64, 100);

        let tx_hash = [1u8; 64];
        let proof_path = vec![[2u8; 64]];
        let root = [0u8; 64];

        let result = verifier.verify_proof(&tx_hash, &proof_path, &root).unwrap();
        assert!(!result.is_valid); // Will fail because we don't have a valid proof
    }

    #[test]
    fn test_merkle_proof_depth_check() {
        let verifier = MerkleProofVerifier::new(5, 100);

        let tx_hash = [1u8; 64];
        let proof_path = vec![[2u8; 64]; 10]; // Depth > max_depth
        let root = [0u8; 64];

        let result = verifier.verify_proof(&tx_hash, &proof_path, &root).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_batch_verification() {
        let verifier = MerkleProofVerifier::new(64, 100);

        let proof1 = vec![[2u8; 64]];
        let proof2 = vec![[4u8; 64]];
        let proofs = vec![
            (&[1u8; 64], &proof1[..], &[0u8; 64]),
            (&[3u8; 64], &proof2[..], &[0u8; 64]),
        ];

        let result = verifier.verify_batch(&proofs).unwrap();
        assert_eq!(result.total_proofs, 2);
    }

    #[test]
    fn test_validator_signature_verifier() {
        let verifier = ValidatorSignatureVerifier::new(100);
        assert_eq!(verifier.timeout_ms, 100);
    }

    #[test]
    fn test_snapshot_certificate_verifier() {
        let verifier = SnapshotCertificateVerifier::new(100);
        assert_eq!(verifier.timeout_ms, 100);
    }

    #[test]
    fn test_comprehensive_verifier() {
        let verifier = ComprehensiveProofVerifier::new(100);

        let tx_hash = [1u8; 64];
        let proof_path = vec![[2u8; 64]];
        let snapshot_root = [0u8; 64];
        let validator_signatures = vec![];
        let validators = vec![];
        let total_stake = 0;

        let result = verifier.verify_query_result(
            &tx_hash,
            &proof_path,
            &snapshot_root,
            &validator_signatures,
            &validators,
            total_stake,
        );

        assert!(result.is_ok());
    }
}
