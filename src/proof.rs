//! State proof generation and verification
//!
//! This module implements cryptographic proofs that allow light clients
//! to verify object state against snapshot state roots without downloading
//! the entire state tree.
//!
//! Uses Merkle proofs to prove inclusion of objects in the state tree.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use silver_core::{Object, ObjectID, StateDigest};
use std::time::Instant;

/// Merkle proof node
#[derive(Debug, Clone)]
pub enum ProofNode {
    /// Left sibling hash
    Left([u8; 64]),
    /// Right sibling hash
    Right([u8; 64]),
}

// Manual Serialize/Deserialize implementation for ProofNode
impl Serialize for ProofNode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            ProofNode::Left(hash) => {
                let mut state = serializer.serialize_struct("ProofNode", 2)?;
                state.serialize_field("type", "Left")?;
                state.serialize_field("hash", &hash.as_slice())?;
                state.end()
            }
            ProofNode::Right(hash) => {
                let mut state = serializer.serialize_struct("ProofNode", 2)?;
                state.serialize_field("type", "Right")?;
                state.serialize_field("hash", &hash.as_slice())?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ProofNode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ProofNodeHelper {
            #[serde(rename = "type")]
            node_type: String,
            hash: Vec<u8>,
        }

        let helper = ProofNodeHelper::deserialize(deserializer)?;
        
        if helper.hash.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                helper.hash.len()
            )));
        }

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&helper.hash);

        match helper.node_type.as_str() {
            "Left" => Ok(ProofNode::Left(hash)),
            "Right" => Ok(ProofNode::Right(hash)),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown ProofNode type: {}",
                helper.node_type
            ))),
        }
    }
}

/// State proof for object inclusion in state tree
///
/// Proves that an object with a specific ID and state exists in the
/// state tree with the given root hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// Object being proven
    pub object: Object,

    /// Merkle proof path from object to root
    pub proof_path: Vec<ProofNode>,

    /// State root this proof is for
    pub state_root: StateDigest,

    /// Proof generation timestamp
    pub timestamp: u64,
}

impl StateProof {
    /// Create a new state proof
    pub fn new(
        object: Object,
        proof_path: Vec<ProofNode>,
        state_root: StateDigest,
    ) -> Self {
        Self {
            object,
            proof_path,
            state_root,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Verify this proof against a state root
    ///
    /// Returns Ok(()) if the proof is valid, Err otherwise.
    /// Verification must complete within 100ms as per requirements.
    pub fn verify(&self) -> Result<()> {
        let start = Instant::now();

        // Compute object hash
        let mut current_hash = self.compute_object_hash(&self.object);

        // Traverse proof path
        for node in &self.proof_path {
            current_hash = match node {
                ProofNode::Left(sibling) => {
                    // Current is right child
                    self.hash_pair(sibling, &current_hash)
                }
                ProofNode::Right(sibling) => {
                    // Current is left child
                    self.hash_pair(&current_hash, sibling)
                }
            };
        }

        // Check if we reached the state root
        if current_hash != *self.state_root.as_bytes() {
            return Err(Error::InvalidProof(format!(
                "Proof verification failed: computed root {:?} != expected root {:?}",
                &current_hash[..8],
                &self.state_root.as_bytes()[..8]
            )));
        }

        // Check verification time (must be < 100ms)
        let elapsed = start.elapsed();
        if elapsed.as_millis() > 100 {
            return Err(Error::VerificationTimeout);
        }

        Ok(())
    }

    /// Compute hash of an object
    fn compute_object_hash(&self, object: &Object) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();

        // Hash object ID
        hasher.update(object.id.as_bytes());

        // Hash version
        hasher.update(&object.version.0.to_le_bytes());

        // Hash owner
        match &object.owner {
            silver_core::Owner::AddressOwner(addr) => {
                hasher.update(&[0u8]); // Owner type tag
                hasher.update(addr.as_bytes());
            }
            silver_core::Owner::Shared {
                initial_shared_version,
            } => {
                hasher.update(&[1u8]); // Owner type tag
                hasher.update(&initial_shared_version.0.to_le_bytes());
            }
            silver_core::Owner::Immutable => {
                hasher.update(&[2u8]); // Owner type tag
            }
            silver_core::Owner::ObjectOwner(obj_id) => {
                hasher.update(&[3u8]); // Owner type tag
                hasher.update(obj_id.as_bytes());
            }
        }

        // Hash data (serialized)
        let data_bytes = bincode::serialize(&object.data).unwrap_or_default();
        hasher.update(&data_bytes);

        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Hash two nodes together
    fn hash_pair(&self, left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(left);
        hasher.update(right);

        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Get the size of this proof in bytes
    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self).map(|b| b.len()).unwrap_or(0)
    }

    /// Get the depth of this proof (number of levels in tree)
    pub fn depth(&self) -> usize {
        self.proof_path.len()
    }
}

/// State proof verifier with caching and optimization
pub struct StateProofVerifier {
    /// Maximum proof depth allowed
    max_depth: usize,

    /// Verification timeout in milliseconds
    timeout_ms: u64,
}

impl StateProofVerifier {
    /// Create a new proof verifier with default settings
    pub fn new() -> Self {
        Self {
            max_depth: 64, // Maximum tree depth
            timeout_ms: 100, // 100ms timeout as per requirements
        }
    }

    /// Create a verifier with custom settings
    pub fn with_config(max_depth: usize, timeout_ms: u64) -> Self {
        Self {
            max_depth,
            timeout_ms,
        }
    }

    /// Verify a state proof
    pub fn verify(&self, proof: &StateProof) -> Result<()> {
        // Check proof depth
        if proof.depth() > self.max_depth {
            return Err(Error::InvalidProof(format!(
                "Proof depth {} exceeds maximum {}",
                proof.depth(),
                self.max_depth
            )));
        }

        // Verify the proof
        proof.verify()
    }

    /// Verify multiple proofs in batch
    ///
    /// Returns a vector of results, one for each proof.
    /// Stops verification if any proof exceeds the timeout.
    pub fn verify_batch(&self, proofs: &[StateProof]) -> Vec<Result<()>> {
        let start = Instant::now();
        let mut results = Vec::with_capacity(proofs.len());

        for proof in proofs {
            // Check if we've exceeded total timeout
            if start.elapsed().as_millis() as u64 > self.timeout_ms * proofs.len() as u64 {
                results.push(Err(Error::VerificationTimeout));
                continue;
            }

            results.push(self.verify(proof));
        }

        results
    }

    /// Verify a proof against a specific state root
    pub fn verify_against_root(
        &self,
        proof: &StateProof,
        expected_root: &StateDigest,
    ) -> Result<()> {
        // Check state root matches
        if proof.state_root != *expected_root {
            return Err(Error::InvalidProof(format!(
                "State root mismatch: proof has {:?}, expected {:?}",
                &proof.state_root.as_bytes()[..8],
                &expected_root.as_bytes()[..8]
            )));
        }

        // Verify the proof
        self.verify(proof)
    }
}

impl Default for StateProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating state proofs (used by full nodes)
pub struct StateProofBuilder {
    object: Option<Object>,
    proof_path: Vec<ProofNode>,
    state_root: Option<StateDigest>,
}

impl StateProofBuilder {
    /// Create a new proof builder
    pub fn new() -> Self {
        Self {
            object: None,
            proof_path: Vec::new(),
            state_root: None,
        }
    }

    /// Set the object to prove
    pub fn object(mut self, object: Object) -> Self {
        self.object = Some(object);
        self
    }

    /// Add a left sibling to the proof path
    pub fn add_left_sibling(mut self, hash: [u8; 64]) -> Self {
        self.proof_path.push(ProofNode::Left(hash));
        self
    }

    /// Add a right sibling to the proof path
    pub fn add_right_sibling(mut self, hash: [u8; 64]) -> Self {
        self.proof_path.push(ProofNode::Right(hash));
        self
    }

    /// Set the state root
    pub fn state_root(mut self, root: StateDigest) -> Self {
        self.state_root = Some(root);
        self
    }

    /// Build the state proof
    pub fn build(self) -> Result<StateProof> {
        let object = self
            .object
            .ok_or_else(|| Error::InvalidProof("No object provided".to_string()))?;

        let state_root = self
            .state_root
            .ok_or_else(|| Error::InvalidProof("No state root provided".to_string()))?;

        Ok(StateProof::new(object, self.proof_path, state_root))
    }
}

impl Default for StateProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_core::{Owner, SilverAddress};
    use silver_core::object::ObjectType;

    fn create_test_object() -> Object {
        Object {
            id: ObjectID::new([1u8; 64]),
            version: silver_core::SequenceNumber::new(1),
            owner: Owner::AddressOwner(SilverAddress::new([2u8; 64])),
            object_type: ObjectType::Coin,
            data: vec![1, 2, 3, 4],
            previous_transaction: silver_core::TransactionDigest::new([3u8; 64]),
            storage_rebate: 0,
        }
    }

    #[test]
    fn test_proof_verification_simple() {
        let object = create_test_object();
        let state_root = StateDigest::new([0u8; 64]);

        // Create a simple proof (empty path for testing)
        let proof = StateProof::new(object, vec![], state_root);

        // This will fail because we don't have a valid proof path
        // but it tests the verification logic
        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_proof_depth() {
        let object = create_test_object();
        let state_root = StateDigest::new([0u8; 64]);

        let mut proof_path = Vec::new();
        for _ in 0..10 {
            proof_path.push(ProofNode::Left([0u8; 64]));
        }

        let proof = StateProof::new(object, proof_path, state_root);
        assert_eq!(proof.depth(), 10);
    }

    #[test]
    fn test_proof_verifier_max_depth() {
        let verifier = StateProofVerifier::with_config(5, 100);

        let object = create_test_object();
        let state_root = StateDigest::new([0u8; 64]);

        // Create proof with depth > max_depth
        let mut proof_path = Vec::new();
        for _ in 0..10 {
            proof_path.push(ProofNode::Left([0u8; 64]));
        }

        let proof = StateProof::new(object, proof_path, state_root);

        // Should fail due to depth
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_proof_builder() {
        let object = create_test_object();
        let state_root = StateDigest::new([0u8; 64]);

        let proof = StateProofBuilder::new()
            .object(object)
            .add_left_sibling([1u8; 64])
            .add_right_sibling([2u8; 64])
            .state_root(state_root)
            .build()
            .unwrap();

        assert_eq!(proof.depth(), 2);
    }

    #[test]
    fn test_proof_size() {
        let object = create_test_object();
        let state_root = StateDigest::new([0u8; 64]);
        let proof = StateProof::new(object, vec![], state_root);

        let size = proof.size_bytes();
        assert!(size > 0);
    }
}
