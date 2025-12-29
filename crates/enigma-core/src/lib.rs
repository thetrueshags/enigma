pub mod models;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use pqcrypto_kyber::kyber1024;
use serde::{Deserialize, Serialize};

use crate::models::SecretRecord;
use axion_crypto::traits::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnigmaPayload {
    pub nonce: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

impl EnigmaPayload {
    pub fn encrypt(secret: &SecretRecord, pubkey_bytes: &[u8]) -> Result<Self> {
        let pk = kyber1024::PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| anyhow!("Crypto Error: Invalid Public Key"))?;

        let (shared_secret, kem_ct) = kyber1024::encapsulate(&pk);

        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let plaintext = bincode::serialize(secret)?;
        let encrypted_data = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("AES Encryption failure: {}", e))?;

        Ok(EnigmaPayload {
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct.as_bytes().to_vec(),
            encrypted_data,
        })
    }

    pub fn decrypt(blob_bytes: &[u8], sk_bytes: &[u8]) -> Result<SecretRecord> {
        let payload: EnigmaPayload = match bincode::deserialize(blob_bytes) {
            Ok(p) => p,
            Err(_) if blob_bytes.len() > 8 => {
                bincode::deserialize(&blob_bytes[8..])
                    .map_err(|e| anyhow!("Inner shell recovery failed: {}", e))?
            }
            Err(e) => return Err(anyhow!("Failed to deserialize Enigma shell: {}", e)),
        };

        let sk = kyber1024::SecretKey::from_bytes(sk_bytes)
            .map_err(|_| anyhow!("Crypto Error: Invalid Secret Key"))?;

        let kem_ct = kyber1024::Ciphertext::from_bytes(&payload.kem_ciphertext)
            .map_err(|_| anyhow!("Crypto Error: Invalid KEM Ciphertext (Length mismatch)"))?;

        let shared_secret = kyber1024::decapsulate(&kem_ct, &sk);
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&payload.nonce);

        let plaintext = cipher
            .decrypt(nonce, payload.encrypted_data.as_ref())
            .map_err(|_| {
                anyhow!("AES Decryption failed: Potential key mismatch or data corruption")
            })?;

        let record: SecretRecord = bincode::deserialize(&plaintext)
            .map_err(|e| anyhow!("Failed to deserialize SecretRecord: {}", e))?;

        Ok(record)
    }
}