use anyhow::{anyhow, Result};
use axion_crypto::{EncryptionKeypair, IdentityPoW, Keypair, PublicKey};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Minimum PoW difficulty required by the Axion L1.
const MIN_POW_DIFFICULTY: u32 = 16;

#[derive(Serialize, Deserialize)]
pub struct PersistentIdentity {
    pub signing: Keypair,
    pub encryption: EncryptionKeypair,
    pub did: String,
    pub pow: IdentityPoW,
}

pub fn get_default_path() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "axion", "enigma") {
        let config_dir = proj_dirs.config_dir();
        if !config_dir.exists() {
            let _ = fs::create_dir_all(config_dir);
        }
        config_dir.join("identity.json")
    } else {
        PathBuf::from("identity.json")
    }
}

pub fn load_or_create(custom_path: Option<String>) -> Result<(PersistentIdentity, PathBuf)> {
    let path = match custom_path {
        Some(p) => PathBuf::from(p),
        None => get_default_path(),
    };

    if path.exists() {
        let content = fs::read(&path)?;
        let id: PersistentIdentity = serde_json::from_slice(&content)?;

        // Verify DID derivation
        let derived_did = PublicKey::from_bytes(&id.signing.public).to_did_hash();
        if derived_did != id.did {
            return Err(anyhow!("Identity file corrupted: DID mismatch"));
        }

        // Verify PoW integrity
        if !id.pow.verify(&id.signing.public) {
            return Err(anyhow!("Identity file corrupted: PoW verification failed"));
        }

        Ok((id, path))
    } else {
        let signing = Keypair::generate();
        let encryption = EncryptionKeypair::generate();
        let did = PublicKey::from_bytes(&signing.public).to_did_hash();
        let pow = IdentityPoW::mint(&signing.public, MIN_POW_DIFFICULTY);

        let id = PersistentIdentity {
            signing,
            encryption,
            did,
            pow,
        };

        let mut file = File::create(&path)?;
        file.write_all(&serde_json::to_vec_pretty(&id)?)?;

        Ok((id, path))
    }
}
