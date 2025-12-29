mod identity;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Password};
use enigma_core::{models::SecretRecord, EnigmaPayload};
use serde_json::json;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "enigma",
    version = "1.0",
    about = "Quantum-Safe Double-Lock Vault"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add,
    List,
}

const AXION_RPC: &str = "http://127.0.0.1:3030";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let id = identity::load_or_create("identity.json")?;
    println!("👤 DID: {}\n", style(&id.did).cyan());

    ensure_identity_registered(&id).await?;

    match cli.command {
        Commands::Add => {
            let title: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Title (e.g. GitHub)")
                .interact_text()?;
            let user: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Username")
                .interact_text()?;
            let pass = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Password")
                .interact()?;

            let record = SecretRecord::new(title, &user, &pass, "Axion Double-Locked");

            println!("🔒 Applying Enigma Encryption (Layer 1)...");
            let inner_payload = EnigmaPayload::encrypt(&record, &id.encryption.public)?;

            let inner_bytes = bincode::serialize(&inner_payload)
                .map_err(|e| anyhow!("Failed to serialize Enigma payload: {}", e))?;

            let raw_did = id.did.replace("did:axion:", "");
            let body = json!({
                "type": "private",
                "recipient": raw_did,
                "data": hex::encode(inner_bytes)
            });

            let client = reqwest::Client::new();
            let res = client
                .post(format!("{}/publish", AXION_RPC))
                .json(&body)
                .send()
                .await?;

            let status = res.status();
            let response_text = res.text().await?;

            if status.is_success() && !response_text.contains("Error") {
                println!("✅ Published to Mesh!");
                println!("📦 Block Hash: {}", style(response_text).green());
            } else {
                println!("❌ Node Rejected Block: {}", style(response_text).red());
            }
        }
        Commands::List => {
            println!(
                "📂 Fetching vault index for DID: {}...",
                style(&id.did).cyan()
            );
            let client = reqwest::Client::new();
            let res = client
                .get(format!("{}/api/vault/{}", AXION_RPC, id.did))
                .send()
                .await?;

            if !res.status().is_success() {
                return Err(anyhow!("Failed to retrieve vault: {}", res.status()));
            }

            let blocks: Vec<axion_core::AxionBlock> = res.json().await?;
            println!("Found {} encrypted records.\n", blocks.len());

            for block in blocks {
                if let axion_core::BlockPayload::DataStore { blob, .. } = &block.payload {
                    if blob.is_empty() {
                        continue;
                    }

                    if let Ok((kem, nonce)) = block.payload.get_keys_for(&id.did) {
                        match axion_crypto::hybrid_decrypt(
                            blob,
                            &kem,
                            &nonce,
                            &id.encryption.secret,
                        ) {
                            Ok(inner_bytes) => {
                                match EnigmaPayload::decrypt(&inner_bytes, &id.encryption.secret) {
                                    Ok(record) => {
                                        println!(
                                            "🔹 [{}] - {} (User: {})",
                                            style(&block.hash[..8]).yellow(),
                                            style(record.title).bold().green(),
                                            record.username
                                        );
                                    }
                                    Err(e) => {
                                        println!("❌ Inner Decrypt Failed: {}", style(e).red());
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Outer Decrypt Failed: {}", style(e).red());
                            }
                        }
                    } else {
                        println!(
                            "⚠️  [{}] - No access keys found for your DID",
                            style(&block.hash[..8]).red()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

async fn ensure_identity_registered(id: &identity::PersistentIdentity) -> Result<()> {
    let client = reqwest::Client::new();
    let body = json!({
        "did": id.did,
        "encryption_key": hex::encode(&id.encryption.public)
    });

    let res = client
        .post(format!("{}/announce_key", AXION_RPC))
        .json(&body)
        .send()
        .await;

    match res {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("📡 Identity synced with local mesh. Waiting for confirmation...");
                tokio::time::sleep(Duration::from_millis(1500)).await;
            } else {
                println!("⚠️  Node Announcement Warning: {}", resp.status());
            }
        }
        Err(_) => {
            return Err(anyhow!(
                "Could not connect to Axion Node at {}. Is it running?",
                AXION_RPC
            ));
        }
    }
    Ok(())
}
