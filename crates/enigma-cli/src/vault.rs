use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use enigma_core::models::SecretRecord;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

const NONCE_SIZE: usize = 12;

/// Local vault data. The mesh is the source of truth; this is a speed cache.
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultData {
    pub version: u32,
    pub records: Vec<SecretRecord>,
    pub last_sync: Option<u64>,
}

impl VaultData {
    fn empty() -> Self {
        Self { version: 1, records: Vec::new(), last_sync: None }
    }
}

/// Derive the vault encryption key from the signing secret key.
/// Uses SHA3-256 with a domain separator to avoid key reuse.
fn derive_vault_key(signing_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"enigma-vault-v1");
    hasher.update(signing_secret);
    hasher.finalize().into()
}

/// Resolve the vault file path as a sibling of the identity file.
pub fn vault_path(identity_path: &Path) -> PathBuf {
    identity_path.with_file_name("vault.enc")
}

/// Load the vault from disk. Returns empty VaultData if the file doesn't exist.
pub fn load(vault_path: &Path, signing_secret: &[u8]) -> Result<VaultData> {
    if !vault_path.exists() {
        return Ok(VaultData::empty());
    }

    let data = std::fs::read(vault_path)?;
    if data.len() < NONCE_SIZE {
        return Err(anyhow!("Vault file too small — may be corrupted"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let key = derive_vault_key(signing_secret);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Vault decryption failed — identity may have changed. Delete vault.enc to start fresh."))?;

    let vault: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|e| anyhow!("Vault data corrupted: {}", e))?;

    Ok(vault)
}

/// Save the vault to disk with AES-256-GCM encryption.
/// Writes to a temp file first, then renames for atomicity.
pub fn save(vault_path: &Path, signing_secret: &[u8], data: &VaultData) -> Result<()> {
    let json = serde_json::to_vec(data)
        .map_err(|e| anyhow!("Vault serialization failed: {}", e))?;

    let key = derive_vault_key(signing_secret);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, json.as_ref())
        .map_err(|_| anyhow!("Vault encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    let tmp_path = vault_path.with_extension("enc.tmp");
    std::fs::write(&tmp_path, &out)?;
    std::fs::rename(&tmp_path, vault_path)?;

    Ok(())
}

/// Search records by case-insensitive substring match on title, url, or username.
pub fn search<'a>(records: &'a [SecretRecord], query: &str) -> Vec<&'a SecretRecord> {
    let q = query.to_lowercase();
    records.iter().filter(|r| {
        r.title.to_lowercase().contains(&q)
            || r.url.to_lowercase().contains(&q)
            || r.username.to_lowercase().contains(&q)
    }).collect()
}

/// Insert or update a record. Deduplicates by (title, username, url).
/// If a matching record exists, replaces it only if the new one is newer.
pub fn upsert(data: &mut VaultData, record: SecretRecord) {
    if let Some(existing) = data.records.iter_mut().find(|r| {
        r.title == record.title && r.username == record.username && r.url == record.url
    }) {
        if record.created_at >= existing.created_at {
            *existing = record;
        }
    } else {
        data.records.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(title: &str, user: &str, url: &str, ts: u64) -> SecretRecord {
        SecretRecord {
            title: title.to_string(),
            username: user.to_string(),
            password: "secret".to_string(),
            notes: String::new(),
            created_at: ts,
            url: url.to_string(),
        }
    }

    fn temp_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        (dir, path)
    }

    // ==================== Load / Save ====================

    #[test]
    fn vault_roundtrip() {
        let (_dir, path) = temp_vault();
        let key = b"test-signing-secret-key-material";
        let mut data = VaultData::empty();
        data.records.push(make_record("GitHub", "user", "https://github.com", 1000));
        data.records.push(make_record("Steam", "gamer", "https://steam.com", 2000));
        data.last_sync = Some(3000);

        save(&path, key, &data).unwrap();
        let loaded = load(&path, key).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.records.len(), 2);
        assert_eq!(loaded.records[0].title, "GitHub");
        assert_eq!(loaded.records[1].title, "Steam");
        assert_eq!(loaded.last_sync, Some(3000));
    }

    #[test]
    fn vault_empty_on_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.enc");
        let data = load(&path, b"key").unwrap();
        assert!(data.records.is_empty());
        assert_eq!(data.version, 1);
    }

    #[test]
    fn vault_wrong_key_fails() {
        let (_dir, path) = temp_vault();
        let data = VaultData::empty();
        save(&path, b"key-a", &data).unwrap();
        let err = load(&path, b"key-b").unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn vault_corrupt_file_fails() {
        let (_dir, path) = temp_vault();
        std::fs::write(&path, vec![0xDE; 20]).unwrap();
        assert!(load(&path, b"any-key").is_err());
    }

    #[test]
    fn vault_too_small_file_fails() {
        let (_dir, path) = temp_vault();
        std::fs::write(&path, &[0u8; 5]).unwrap();
        let err = load(&path, b"key").unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    // ==================== Search ====================

    #[test]
    fn search_case_insensitive() {
        let records = vec![make_record("GitHub", "user", "", 0)];
        assert_eq!(search(&records, "github").len(), 1);
        assert_eq!(search(&records, "GITHUB").len(), 1);
        assert_eq!(search(&records, "Git").len(), 1);
    }

    #[test]
    fn search_by_url() {
        let records = vec![make_record("Site", "u", "https://github.com", 0)];
        assert_eq!(search(&records, "github.com").len(), 1);
    }

    #[test]
    fn search_by_username() {
        let records = vec![make_record("Site", "john@example.com", "", 0)];
        assert_eq!(search(&records, "john").len(), 1);
    }

    #[test]
    fn search_no_match() {
        let records = vec![make_record("GitHub", "user", "", 0)];
        assert!(search(&records, "nonexistent").is_empty());
    }

    #[test]
    fn search_multiple_matches() {
        let records = vec![
            make_record("GitHub Personal", "user1", "", 0),
            make_record("GitHub Work", "user2", "", 0),
            make_record("Steam", "gamer", "", 0),
        ];
        assert_eq!(search(&records, "github").len(), 2);
    }

    // ==================== Upsert ====================

    #[test]
    fn upsert_new_record() {
        let mut data = VaultData::empty();
        upsert(&mut data, make_record("New", "u", "", 1000));
        assert_eq!(data.records.len(), 1);
        assert_eq!(data.records[0].title, "New");
    }

    #[test]
    fn upsert_dedup_replaces_newer() {
        let mut data = VaultData::empty();
        upsert(&mut data, make_record("Site", "u", "", 1000));
        assert_eq!(data.records[0].password, "secret");

        let mut newer = make_record("Site", "u", "", 2000);
        newer.password = "updated".to_string();
        upsert(&mut data, newer);

        assert_eq!(data.records.len(), 1, "should not duplicate");
        assert_eq!(data.records[0].password, "updated");
    }

    #[test]
    fn upsert_keeps_newer_existing() {
        let mut data = VaultData::empty();
        let mut existing = make_record("Site", "u", "", 2000);
        existing.password = "newer_pass".to_string();
        upsert(&mut data, existing);

        let older = make_record("Site", "u", "", 1000);
        upsert(&mut data, older);

        assert_eq!(data.records.len(), 1);
        assert_eq!(data.records[0].password, "newer_pass", "should keep the newer record");
    }

    #[test]
    fn upsert_different_url_is_separate() {
        let mut data = VaultData::empty();
        upsert(&mut data, make_record("Site", "u", "https://a.com", 1000));
        upsert(&mut data, make_record("Site", "u", "https://b.com", 1000));
        assert_eq!(data.records.len(), 2, "different urls should be separate records");
    }
}
