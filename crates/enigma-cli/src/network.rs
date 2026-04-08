use anyhow::Result;
use enigma_core::{models::SecretRecord, EnigmaPayload};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{identity::PersistentIdentity, vault};

/// Fetch all secrets from the Axion mesh addressed to this identity, decrypt both layers.
pub async fn fetch_and_decrypt(
    client: &reqwest::Client,
    rpc: &str,
    id: &PersistentIdentity,
) -> Result<Vec<SecretRecord>> {
    let res = client
        .get(format!("{}/api/blocks", rpc))
        .query(&[("recipient", &id.did), ("limit", &"500".to_string())])
        .send()
        .await?;

    if !res.status().is_success() {
        return Ok(Vec::new());
    }

    let blocks: Vec<axion_core::AxionBlock> = res.json().await?;
    let mut records = Vec::new();

    for block in &blocks {
        if let axion_core::BlockPayload::DataStore { blob, .. } = &block.payload {
            let decrypted_blob = if blob.is_empty() {
                match client.get(format!("{}/retrieve/{}", rpc, block.hash)).send().await {
                    Ok(r) => {
                        let body: serde_json::Value = r.json().await.unwrap_or_default();
                        match body["data"].as_str().and_then(|h| hex::decode(h).ok()) {
                            Some(d) => d,
                            None => continue,
                        }
                    }
                    Err(_) => continue,
                }
            } else {
                match block.payload.get_keys_for(&id.did) {
                    Ok((kem, nonce)) => {
                        match axion_crypto::hybrid_decrypt(blob, &kem, &nonce, &id.encryption.secret) {
                            Ok(bytes) => bytes,
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            };

            if let Ok(record) = EnigmaPayload::decrypt(&decrypted_blob, &id.encryption.secret) {
                records.push(record);
            }
        }
    }

    Ok(records)
}

/// Pull secrets from the mesh and upsert into the local vault.
pub async fn sync_from_network(
    client: &reqwest::Client,
    rpc: &str,
    id: &PersistentIdentity,
    vault_path: &Path,
) -> Result<usize> {
    let records = fetch_and_decrypt(client, rpc, id).await?;
    let count = records.len();

    let mut vault_data = vault::load(vault_path, &id.signing.secret)?;
    for record in records {
        vault::upsert(&mut vault_data, record);
    }
    vault_data.last_sync = Some(
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    );
    vault::save(vault_path, &id.signing.secret, &vault_data)?;

    Ok(count)
}
