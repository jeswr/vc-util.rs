//! Ed25519 signature validation for preprocessed documents.
//! This module provides functionality to validate Ed25519 signatures on preprocessed documents
//! that contain canonical proof and document data.

use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct VerifyInput<'a> {
    canonical_document: &'a str,
    canonical_proof: &'a str,
    public_key: &'a str,
    proof: &'a str,
}

pub fn ed25519_verify(verify: VerifyInput) -> Result<(), String> {
    let mut message_bytes = Vec::with_capacity(64); // 32 bytes for each hash

    // 1. Hash the canonical proof and document
    let mut hasher = Sha256::new();
    hasher.update(verify.canonical_proof.as_bytes());
    message_bytes.extend_from_slice(&hasher.finalize());

    let mut hasher = Sha256::new();
    hasher.update(verify.canonical_document.as_bytes());
    message_bytes.extend_from_slice(&hasher.finalize());

    let public_key_bytes = bs58::decode(verify.public_key)
        .into_vec()
        .map_err(|_| "Failed to decode base58 public key")?;

    let signature_bytes = bs58::decode(verify.proof)
        .into_vec()
        .map_err(|_| "Failed to decode base58 signature")?;

    // Verify the signature against the concatenated hash
    VerifyingKey::from_bytes(&public_key_bytes[2..].try_into().unwrap())
        .unwrap()
        .verify(&message_bytes, &Signature::from_bytes(&signature_bytes.try_into().unwrap()))
        .map_err(|_| "Signature verification failed")?;

    Ok(())
}
