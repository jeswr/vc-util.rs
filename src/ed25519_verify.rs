//! Ed25519 signature validation for preprocessed documents.
//! This module provides functionality to validate Ed25519 signatures on preprocessed documents
//! that contain canonical proof and document data.

use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Ed25519Preprocessed;

#[derive(Serialize, Deserialize)]
pub struct VerifyInput {
    pub canonical_document: String,
    pub canonical_proof: String,
    pub public_key: String,
    pub proof: String,
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
        .verify(
            &message_bytes,
            &Signature::from_bytes(&signature_bytes.try_into().unwrap()),
        )
        .map_err(|_| "Signature verification failed")?;

    Ok(())
}

pub fn ed25519_verify_input_from_preprocessed(
    preprocessed: Ed25519Preprocessed,
) -> Result<VerifyInput, String> {
    // Remove the 'z' prefix and decode base58
    let public_key_multibase = &preprocessed.verification_method.public_key_multibase;
    if !public_key_multibase.starts_with('z') {
        return Err("Invalid public key multibase format".to_string());
    }

    // Decode the proof value (remove 'z' prefix and decode base58)
    let proof_value = &preprocessed.proof.proof_value;
    if !proof_value.starts_with('z') {
        return Err("Invalid proof value format".to_string());
    }

    return Ok(VerifyInput {
        canonical_document: preprocessed.verify_data.canonical_document,
        canonical_proof: preprocessed.verify_data.canonical_proof,
        public_key: public_key_multibase[1..].to_string(),
        proof: proof_value[1..].to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ed25519_verify_from_preprocessed() {
        // Read the preprocessed JSON file
        let json_str = fs::read_to_string("ed25519-preprocessed.json")
            .expect("Failed to read ed25519-preprocessed.json");

        // Parse the JSON into Ed25519Preprocessed struct
        let preprocessed: Ed25519Preprocessed =
            serde_json::from_str(&json_str).expect("Failed to parse preprocessed JSON");

        // Convert to VerifyInput
        let verify_input = ed25519_verify_input_from_preprocessed(preprocessed)
            .expect("Failed to create verify input");

        // Verify the signature
        ed25519_verify(verify_input).expect("Signature verification failed");
    }

    #[test]
    fn test_ed25519_verify_with_serialization() {
        // Read the preprocessed JSON file
        let json_str = fs::read_to_string("ed25519-preprocessed.json")
            .expect("Failed to read ed25519-preprocessed.json");

        // Parse the JSON into Ed25519Preprocessed struct
        let preprocessed: Ed25519Preprocessed =
            serde_json::from_str(&json_str).expect("Failed to parse preprocessed JSON");

        // Convert to VerifyInput
        let verify_input = ed25519_verify_input_from_preprocessed(preprocessed)
            .expect("Failed to create verify input");

        // Serialize to string
        let serialized =
            serde_json::to_string(&verify_input).expect("Failed to serialize verify input");

        // Deserialize back to VerifyInput
        let deserialized: VerifyInput =
            serde_json::from_str(&serialized).expect("Failed to deserialize verify input");

        // Verify the signature
        ed25519_verify(deserialized).expect("Signature verification failed");
    }
}
