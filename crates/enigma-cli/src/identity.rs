use anyhow::{anyhow, Result};
use axion_crypto::{EncryptionKeypair, Keypair, PublicKey};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
pub struct PersistentIdentity {
    pub signing: Keypair,
    pub encryption: EncryptionKeypair,
    pub did: String,
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

        let derived_did = PublicKey::from_bytes(&id.signing.public).to_did_hash();
        if derived_did != id.did {
            return Err(anyhow!("🚨 CRITICAL: Identity file corrupted or tampered!"));
        }
        Ok((id, path))
    } else {
        let signing = Keypair::generate();
        let encryption = EncryptionKeypair::generate();
        let did = PublicKey::from_bytes(&signing.public).to_did_hash();

        let id = PersistentIdentity {
            signing,
            encryption,
            did,
        };

        let mut file = File::create(&path)?;
        file.write_all(&serde_json::to_vec_pretty(&id)?)?;

        Ok((id, path))
    }
}