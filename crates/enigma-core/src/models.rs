use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRecord {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: u64,
}

impl SecretRecord {
    pub fn new(title: String, username: &str, password: &str, notes: &str) -> Self {
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
        }
    }
}