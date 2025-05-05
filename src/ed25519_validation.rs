//! Ed25519 signature validation for preprocessed documents.
//! This module provides functionality to validate Ed25519 signatures on preprocessed documents
//! that contain canonical proof and document data.

use serde::Deserialize;
use sha2::{Sha256, Digest};
use bs58;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use hex;

#[derive(Debug, Deserialize)]
pub struct Ed25519Preprocessed {
    #[serde(rename = "verifyData")]
    pub verify_data: VerifyData,
    #[serde(rename = "verificationMethod")]
    pub verification_method: VerificationMethod,
    pub proof: Proof,
}

#[derive(Debug, Deserialize)]
pub struct VerifyData {
    #[serde(rename = "proofHash")]
    pub proof_hash: String,
    #[serde(rename = "docHash")]
    pub doc_hash: String,
    #[serde(rename = "concatHash")]
    pub concat_hash: String,
    #[serde(rename = "canonicalProof")]
    pub canonical_proof: String,
    #[serde(rename = "canonicalDocument")]
    pub canonical_document: String,
}

#[derive(Debug, Deserialize)]
pub struct VerificationMethod {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_field: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl Ed25519Preprocessed {
    pub fn validate(&self) -> Result<(), String> {
        // 1. Hash the canonical proof and document
        let proof_hash = self.hash_string(&self.verify_data.canonical_proof);
        let doc_hash = self.hash_string(&self.verify_data.canonical_document);
        
        // 2. Check that hashes match the stored values
        if proof_hash != self.verify_data.proof_hash {
            return Err("Proof hash mismatch".to_string());
        }
        if doc_hash != self.verify_data.doc_hash {
            return Err("Document hash mismatch".to_string());
        }

        // 3. Check concatenated hash
        let concat = format!("{}{}", proof_hash, doc_hash);
        if concat != self.verify_data.concat_hash {
            return Err("Concatenated hash mismatch".to_string());
        }

        // 4. Verify the signature
        self.verify_signature()?;

        Ok(())
    }

    fn hash_string(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn verify_signature(&self) -> Result<(), String> {
        // Remove the 'z' prefix and decode base58
        let public_key_multibase = &self.verification_method.public_key_multibase;
        if !public_key_multibase.starts_with('z') {
            return Err("Invalid public key multibase format".to_string());
        }
        
        let base58_key = &public_key_multibase[1..];
        let public_key_bytes = bs58::decode(base58_key)
            .into_vec()
            .map_err(|_| "Failed to decode base58 public key")?;

        // Skip the multicodec prefix (0xed01 for Ed25519)
        if public_key_bytes.len() < 2 {
            return Err("Invalid public key length".to_string());
        }
        let public_key_bytes = &public_key_bytes[2..];

        if public_key_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }

        // Convert to Ed25519 verifying key
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|_| "Invalid Ed25519 public key")?;

        // Decode the proof value (remove 'z' prefix and decode base58)
        let proof_value = &self.proof.proof_value;
        if !proof_value.starts_with('z') {
            return Err("Invalid proof value format".to_string());
        }

        let base58_proof = &proof_value[1..];
        let signature_bytes = bs58::decode(base58_proof)
            .into_vec()
            .map_err(|_| "Failed to decode base58 signature")?;

        if signature_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }

        // Create signature from bytes
        let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());

        // Decode the hex-encoded hash
        let message_bytes = hex::decode(&self.verify_data.concat_hash)
            .map_err(|_| "Failed to decode hex hash")?;

        // Verify the signature against the concatenated hash
        verifying_key.verify(
            &message_bytes,
            &signature
        ).map_err(|_| "Signature verification failed")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ed25519_validation() {
        // Read the test JSON file
        let json_str = fs::read_to_string("ed25519-preprocessed.json")
            .expect("Failed to read test file");

        // Parse the JSON into our struct
        let preprocessed: Ed25519Preprocessed = serde_json::from_str(&json_str)
            .expect("Failed to parse JSON");

        // Run the validation
        let result = preprocessed.validate();
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }
} 