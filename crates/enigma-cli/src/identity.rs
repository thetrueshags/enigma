use axion_crypto::{Keypair, EncryptionKeypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
// REMOVED: Context (it was unused)
use anyhow::{anyhow, Result};

#[derive(Serialize, Deserialize)]
pub struct PersistentIdentity {
    pub signing: Keypair,
    pub encryption: EncryptionKeypair,
    pub did: String,
}

pub fn load_or_create(path: &str) -> Result<PersistentIdentity> {
    if std::path::Path::new(path).exists() {
        let content = fs::read(path)?;
        let id: PersistentIdentity = serde_json::from_slice(&content)?;

        // Ensure DID is valid
        let derived_did = PublicKey::from_bytes(&id.signing.public).to_did_hash();
        if derived_did != id.did {
            return Err(anyhow!("Critical: Identity file tampered! DID mismatch."));
        }
        Ok(id)
    } else {
        let signing = Keypair::generate();
        let encryption = EncryptionKeypair::generate();
        let did = PublicKey::from_bytes(&signing.public).to_did_hash();

        // FIX: Use did.clone() so that 'did' is still available for the println! below
        let id = PersistentIdentity {
            signing,
            encryption,
            did: did.clone()
        };

        let mut file = File::create(path)?;
        file.write_all(&serde_json::to_vec_pretty(&id)?)?;

        // Now 'did' is still valid here
        println!("✨ New Identity Generated: {}", did);
        Ok(id)
    }
}