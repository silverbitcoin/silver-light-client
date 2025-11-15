//! Error types for light client operations

use thiserror::Error;

/// Result type for light client operations
pub type Result<T> = std::result::Result<T, Error>;

/// Light client error types
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid snapshot certificate
    #[error("Invalid snapshot certificate: {0}")]
    InvalidCertificate(String),

    /// Insufficient stake weight
    #[error("Insufficient stake weight: {current} / {required} (need 2/3+)")]
    InsufficientStake {
        /// Current stake weight
        current: u64,
        /// Required stake weight
        required: u64,
    },

    /// Invalid state proof
    #[error("Invalid state proof: {0}")]
    InvalidProof(String),

    /// Proof verification timeout
    #[error("Proof verification exceeded 100ms timeout")]
    VerificationTimeout,

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Sync error
    #[error("Synchronization error: {0}")]
    Sync(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Core error
    #[error("Core error: {0}")]
    Core(#[from] silver_core::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("{0}")]
    Other(String),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}
