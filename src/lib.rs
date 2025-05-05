//! VC-Utils library for working with Verifiable Credentials
//! 
//! This library provides utilities for working with Verifiable Credentials,
//! including Ed25519 signature validation for preprocessed documents.

pub mod ed25519_validation;

// Re-export the main types for convenience
pub use ed25519_validation::Ed25519Preprocessed;
