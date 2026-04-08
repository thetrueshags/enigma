use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: u64,
    #[serde(default)]
    pub url: String,
}

impl SecretRecord {
    pub fn new(title: String, username: &str, password: &str, notes: &str, url: &str) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            title,
            username: username.to_string(),
            password: password.to_string(),
            notes: notes.to_string(),
            created_at,
            url: url.to_string(),
        }
    }
}

/// Original 5-field format for backward-compatible bincode deserialization.
/// Bincode is position-based (not self-describing), so old payloads without
/// the `url` field cannot deserialize into the new SecretRecord directly.
#[derive(Serialize, Deserialize)]
pub(crate) struct LegacySecretRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: u64,
}

impl From<LegacySecretRecord> for SecretRecord {
    fn from(old: LegacySecretRecord) -> Self {
        Self {
            title: old.title,
            username: old.username,
            password: old.password,
            notes: old.notes,
            created_at: old.created_at,
            url: String::new(),
        }
    }
}
