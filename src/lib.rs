//! # SilverBitcoin Light Client
//!
//! Light client implementation for SilverBitcoin blockchain that enables
//! mobile and resource-constrained devices to verify blockchain state
//! without downloading full node data.
//!
//! ## Features
//!
//! - Compact snapshot certificate generation and verification
//! - State proof verification against snapshot roots
//! - Efficient synchronization with <10MB bandwidth per day
//! - Detection of invalid proofs within 100ms
//!
//! ## Architecture
//!
//! The light client operates by:
//! 1. Downloading compact snapshot certificates from full nodes
//! 2. Verifying validator signatures represent 2/3+ stake weight
//! 3. Querying object state with cryptographic proofs
//! 4. Validating proofs against snapshot state roots

#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![allow(missing_docs)] // Internal implementation details

pub mod cache;
pub mod certificate;
pub mod client;
pub mod error;
pub mod proof;
pub mod query;
pub mod sync;
pub mod verification;

pub use cache::{CacheStats, QueryResponseCache, TieredCacheStats, TieredQueryCache};
pub use certificate::{SnapshotCertificate, SnapshotCertificateBuilder};
pub use client::{LightClient, LightClientConfig, SyncStatus};
pub use error::{Error, Result};
pub use proof::{StateProof, StateProofVerifier};
pub use query::{
    CacheStats as QueryCacheStats, MerkleProofData, QueryFilter, QueryHandler, QueryResponse,
    QueryResult,
};
pub use sync::{SyncConfig, SyncManager};
pub use verification::{
    BatchVerificationResult, ComprehensiveProofVerifier, MerkleProofVerifier,
    SnapshotCertificateVerifier, ValidatorSignatureVerifier, VerificationResult,
};
