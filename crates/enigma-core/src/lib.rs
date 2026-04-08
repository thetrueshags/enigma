pub mod models;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use pqcrypto_kyber::kyber1024;
use serde::{Deserialize, Serialize};

use crate::models::{LegacySecretRecord, SecretRecord};
use axion_crypto::traits::*;

/// AES-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Enigma Layer 1 encrypted payload. Contains the KEM ciphertext, AES nonce,
/// and the AES-256-GCM encrypted SecretRecord.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnigmaPayload {
    pub nonce: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

impl EnigmaPayload {
    /// Encrypt a SecretRecord using the recipient's Kyber-1024 public key.
    pub fn encrypt(secret: &SecretRecord, pubkey_bytes: &[u8]) -> Result<Self> {
        let pk = kyber1024::PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| anyhow!("Crypto Error: Invalid Kyber-1024 Public Key"))?;

        let (shared_secret, kem_ct) = kyber1024::encapsulate(&pk);

        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let plaintext = bincode::serialize(secret)
            .map_err(|e| anyhow!("Serialization failed: {}", e))?;
        let encrypted_data = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("AES-256-GCM encryption failed: {}", e))?;

        Ok(EnigmaPayload {
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct.as_bytes().to_vec(),
            encrypted_data,
        })
    }

    /// Decrypt an EnigmaPayload from raw bytes using the recipient's Kyber-1024
    /// secret key. Returns the decrypted SecretRecord.
    ///
    /// Supports backward compatibility: if the inner bincode payload was
    /// encrypted with the old 5-field format (no `url`), falls back to
    /// LegacySecretRecord deserialization and converts.
    pub fn decrypt(blob_bytes: &[u8], sk_bytes: &[u8]) -> Result<SecretRecord> {
        let payload: EnigmaPayload = bincode::deserialize(blob_bytes)
            .map_err(|e| anyhow!("Failed to deserialize EnigmaPayload: {}", e))?;

        if payload.nonce.len() != NONCE_SIZE {
            return Err(anyhow!(
                "Invalid nonce length: expected {} bytes, got {}",
                NONCE_SIZE, payload.nonce.len()
            ));
        }

        let sk = kyber1024::SecretKey::from_bytes(sk_bytes)
            .map_err(|_| anyhow!("Invalid Kyber-1024 Secret Key"))?;

        let kem_ct = kyber1024::Ciphertext::from_bytes(&payload.kem_ciphertext)
            .map_err(|_| anyhow!("Invalid KEM Ciphertext"))?;

        let shared_secret = kyber1024::decapsulate(&kem_ct, &sk);
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&payload.nonce);

        let plaintext = cipher
            .decrypt(nonce, payload.encrypted_data.as_ref())
            .map_err(|_| anyhow!("AES decryption failed: key mismatch or data corruption"))?;

        // Try new format first, fall back to legacy (pre-url) format
        match bincode::deserialize::<SecretRecord>(&plaintext) {
            Ok(record) => Ok(record),
            Err(_) => {
                let legacy: LegacySecretRecord = bincode::deserialize(&plaintext)
                    .map_err(|e| anyhow!("Failed to deserialize SecretRecord: {}", e))?;
                Ok(SecretRecord::from(legacy))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axion_crypto::EncryptionKeypair;

    fn test_record() -> SecretRecord {
        SecretRecord::new(
            "GitHub".to_string(), "user@example.com", "hunter2", "main account",
            "https://github.com",
        )
    }

    /// Simulate encrypting a legacy (pre-url) record, as old Enigma versions did.
    fn encrypt_legacy_payload(
        title: &str, username: &str, password: &str, notes: &str,
        created_at: u64, pubkey: &[u8],
    ) -> Vec<u8> {
        let legacy = LegacySecretRecord {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            notes: notes.to_string(),
            created_at,
        };
        let pk = kyber1024::PublicKey::from_bytes(pubkey).unwrap();
        let (shared_secret, kem_ct) = kyber1024::encapsulate(&pk);
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let plaintext = bincode::serialize(&legacy).unwrap();
        let encrypted = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let payload = EnigmaPayload {
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct.as_bytes().to_vec(),
            encrypted_data: encrypted,
        };
        bincode::serialize(&payload).unwrap()
    }

    // ==================== Encrypt / Decrypt ====================

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ekp = EncryptionKeypair::generate();
        let record = test_record();
        let payload = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        let decrypted = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap();
        assert_eq!(decrypted.title, record.title);
        assert_eq!(decrypted.username, record.username);
        assert_eq!(decrypted.password, record.password);
        assert_eq!(decrypted.notes, record.notes);
        assert_eq!(decrypted.url, "https://github.com");
    }

    #[test]
    fn encrypt_decrypt_empty_fields() {
        let ekp = EncryptionKeypair::generate();
        let record = SecretRecord::new(String::new(), "", "", "", "");
        let payload = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        let decrypted = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap();
        assert!(decrypted.title.is_empty());
        assert!(decrypted.username.is_empty());
        assert!(decrypted.url.is_empty());
    }

    #[test]
    fn encrypt_decrypt_large_notes() {
        let ekp = EncryptionKeypair::generate();
        let notes = "x".repeat(100_000);
        let record = SecretRecord::new("big".into(), "u", "p", &notes, "");
        let payload = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        let decrypted = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap();
        assert_eq!(decrypted.notes, notes);
    }

    #[test]
    fn encrypt_produces_unique_ciphertexts() {
        let ekp = EncryptionKeypair::generate();
        let record = test_record();
        let p1 = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        let p2 = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        assert_ne!(p1.nonce, p2.nonce, "nonces must be unique");
        assert_ne!(p1.encrypted_data, p2.encrypted_data);
    }

    // ==================== URL Field ====================

    #[test]
    fn new_record_has_url() {
        let r = SecretRecord::new("Test".into(), "u", "p", "n", "https://example.com");
        assert_eq!(r.url, "https://example.com");
        let bytes = bincode::serialize(&r).unwrap();
        let r2: SecretRecord = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r2.url, "https://example.com");
    }

    #[test]
    fn encrypt_decrypt_with_url() {
        let ekp = EncryptionKeypair::generate();
        let record = SecretRecord::new(
            "Steam".into(), "gamer", "pass123", "gaming", "https://store.steampowered.com",
        );
        let payload = EnigmaPayload::encrypt(&record, &ekp.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        let decrypted = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap();
        assert_eq!(decrypted.url, "https://store.steampowered.com");
        assert_eq!(decrypted.title, "Steam");
    }

    // ==================== Legacy Backward Compatibility ====================

    #[test]
    fn legacy_record_bincode_deserialization() {
        // Simulate old 5-field format serialized with bincode
        let legacy = LegacySecretRecord {
            title: "OldSite".to_string(),
            username: "old_user".to_string(),
            password: "old_pass".to_string(),
            notes: "old notes".to_string(),
            created_at: 1700000000,
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        // New struct cannot deserialize old bincode directly (position-based)
        assert!(bincode::deserialize::<SecretRecord>(&bytes).is_err());
        // But LegacySecretRecord can, and converts to SecretRecord
        let parsed: LegacySecretRecord = bincode::deserialize(&bytes).unwrap();
        let converted = SecretRecord::from(parsed);
        assert_eq!(converted.title, "OldSite");
        assert_eq!(converted.url, "", "legacy records should have empty url");
    }

    #[test]
    fn decrypt_old_payload_without_url() {
        let ekp = EncryptionKeypair::generate();
        // Encrypt using the old format (no url field in bincode)
        let blob = encrypt_legacy_payload(
            "LegacySite", "legacy_user", "legacy_pass", "legacy notes",
            1700000000, &ekp.public,
        );
        // Decrypt with new code should succeed via fallback path
        let record = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap();
        assert_eq!(record.title, "LegacySite");
        assert_eq!(record.username, "legacy_user");
        assert_eq!(record.password, "legacy_pass");
        assert_eq!(record.url, "", "legacy payloads should have empty url after conversion");
    }

    // ==================== Decryption Failures ====================

    #[test]
    fn decrypt_wrong_key_fails() {
        let ekp_a = EncryptionKeypair::generate();
        let ekp_b = EncryptionKeypair::generate();
        let payload = EnigmaPayload::encrypt(&test_record(), &ekp_a.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        assert!(EnigmaPayload::decrypt(&blob, &ekp_b.secret).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let ekp = EncryptionKeypair::generate();
        let mut payload = EnigmaPayload::encrypt(&test_record(), &ekp.public).unwrap();
        payload.encrypted_data[0] ^= 0xFF;
        let blob = bincode::serialize(&payload).unwrap();
        assert!(EnigmaPayload::decrypt(&blob, &ekp.secret).is_err());
    }

    #[test]
    fn decrypt_tampered_kem_ct_fails() {
        let ekp = EncryptionKeypair::generate();
        let mut payload = EnigmaPayload::encrypt(&test_record(), &ekp.public).unwrap();
        payload.kem_ciphertext[0] ^= 0xFF;
        let blob = bincode::serialize(&payload).unwrap();
        assert!(EnigmaPayload::decrypt(&blob, &ekp.secret).is_err());
    }

    #[test]
    fn decrypt_bad_nonce_length_fails() {
        let ekp = EncryptionKeypair::generate();
        let mut payload = EnigmaPayload::encrypt(&test_record(), &ekp.public).unwrap();
        payload.nonce = vec![0u8; 8];
        let blob = bincode::serialize(&payload).unwrap();
        let err = EnigmaPayload::decrypt(&blob, &ekp.secret).unwrap_err();
        assert!(err.to_string().contains("nonce length"));
    }

    #[test]
    fn decrypt_garbage_bytes_fails() {
        let ekp = EncryptionKeypair::generate();
        assert!(EnigmaPayload::decrypt(&[0xDE, 0xAD], &ekp.secret).is_err());
    }

    #[test]
    fn decrypt_empty_bytes_fails() {
        let ekp = EncryptionKeypair::generate();
        assert!(EnigmaPayload::decrypt(&[], &ekp.secret).is_err());
    }

    // ==================== Encryption Failures ====================

    #[test]
    fn encrypt_invalid_pubkey_fails() {
        assert!(EnigmaPayload::encrypt(&test_record(), &[0u8; 100]).is_err());
    }

    #[test]
    fn decrypt_invalid_secret_key_fails() {
        let ekp = EncryptionKeypair::generate();
        let payload = EnigmaPayload::encrypt(&test_record(), &ekp.public).unwrap();
        let blob = bincode::serialize(&payload).unwrap();
        assert!(EnigmaPayload::decrypt(&blob, &[0u8; 100]).is_err());
    }

    // ==================== SecretRecord ====================

    #[test]
    fn secret_record_has_timestamp() {
        let r = SecretRecord::new("t".into(), "u", "p", "n", "");
        assert!(r.created_at > 0);
    }

    #[test]
    fn secret_record_serialization_roundtrip() {
        let r = test_record();
        let bytes = bincode::serialize(&r).unwrap();
        let r2: SecretRecord = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r.title, r2.title);
        assert_eq!(r.password, r2.password);
        assert_eq!(r.url, r2.url);
    }

    #[test]
    fn secret_record_json_default_url() {
        // JSON is self-describing, so #[serde(default)] works for vault cache
        let json = r#"{"title":"T","username":"U","password":"P","notes":"N","created_at":0}"#;
        let r: SecretRecord = serde_json::from_str(json).unwrap();
        assert_eq!(r.url, "", "missing url in JSON should default to empty");
    }
}
