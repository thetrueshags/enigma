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
    about = "Axion Layer 2: Quantum-Safe Vault"
)]
struct Cli {
    /// URL of the Axion Node to connect to
    #[arg(long, default_value = "http://127.0.0.1:3030")]
    rpc: String,

    /// Path to identity file (defaults to system config)
    #[arg(long, short = 'k')]
    keyfile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt and upload a new secret
    Add,
    /// List and decrypt all secrets from the mesh
    List,
    /// Announce identity to the network (required once)
    Sync,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1. Load Identity
    let (id, key_path) = identity::load_or_create(cli.keyfile)?;
    println!(
        "🔑 Identity loaded from: {}",
        style(key_path.to_string_lossy()).dim()
    );
    println!("👤 DID: {}\n", style(&id.did).cyan().bold());

    // 2. Check Connection
    let client = reqwest::Client::new();
    if client.get(&cli.rpc).send().await.is_err() {
        println!(
            "❌ {} Could not connect to Axion Node at {}",
            style("ERROR:").red(),
            cli.rpc
        );
        println!("   Ensure the node is running or specify a remote node with --rpc");
        return Ok(());
    }

    match cli.command {
        Commands::Sync => {
            ensure_identity_registered(&client, &cli.rpc, &id).await?;
        }
        Commands::Add => {
            let title: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Title")
                .interact_text()?;
            let user: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Username")
                .interact_text()?;
            let pass = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Password")
                .interact()?;
            let notes: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Notes")
                .allow_empty(true)
                .interact_text()?;

            println!("🔒 Encrypting...");

            // Layer 1: Enigma (Client-Side)
            let record = SecretRecord::new(title, &user, &pass, &notes);
            let inner_payload = EnigmaPayload::encrypt(&record, &id.encryption.public)?;
            let inner_bytes = bincode::serialize(&inner_payload)?;

            // Layer 2: Axion (Transport)
            // FIX: Do NOT strip the "did:axion:" prefix. The node needs the full DID to look up keys.
            let body = json!({
                "type": "private",
                "recipient": id.did,
                "data": hex::encode(inner_bytes)
            });

            let res = client
                .post(format!("{}/publish", cli.rpc))
                .json(&body)
                .send()
                .await?;
            let response_text = res.text().await?;

            // Check if the response body contains an error message (even if HTTP status is 200)
            if response_text.contains("Error") {
                println!("❌ Upload Failed: {}", style(response_text).red());
                println!("   (Tip: Have you run 'enigma sync' to register your identity?)");
            } else {
                println!("✅ Secret Uploaded! Hash: {}", style(response_text).green());
            }
        }
        Commands::List => {
            println!("📥 Querying public mesh for relevant data...");

            let res = client
                .get(format!("{}/api/blocks", cli.rpc))
                .query(&[("recipient", &id.did), ("limit", &"100".to_string())])
                .send()
                .await?;

            if !res.status().is_success() {
                println!("❌ Failed to query mesh. Status: {}", res.status());
                return Ok(());
            }

            let blocks: Vec<axion_core::AxionBlock> = res.json().await?;
            if blocks.is_empty() {
                println!("📭 No records found in recent history.");
                return Ok(());
            }

            println!("🔓 Decrypting {} relevant blocks...\n", blocks.len());

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
                            Ok(enigma_bytes) => {
                                match EnigmaPayload::decrypt(&enigma_bytes, &id.encryption.secret) {
                                    Ok(record) => {
                                        println!("🔹 {}", style(&record.title).bold().green());
                                        println!("   User: {}", record.username);
                                        println!("   Pass: {}", style(record.password).dim());
                                        println!("   Note: {}\n", style(record.notes).italic());
                                    }
                                    Err(_) => println!(
                                        "⚠️  Corrupt Enigma Payload in Block {}",
                                        &block.hash[..8]
                                    ),
                                }
                            }
                            Err(_) => println!(
                                "⚠️  Failed to unwrap Axion Transport Layer for {}",
                                &block.hash[..8]
                            ),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn ensure_identity_registered(
    client: &reqwest::Client,
    rpc: &str,
    id: &identity::PersistentIdentity,
) -> Result<()> {
    let body = json!({ "did": id.did, "encryption_key": hex::encode(&id.encryption.public) });
    let res = client
        .post(format!("{}/announce_key", rpc))
        .json(&body)
        .send()
        .await?;

    if res.status().is_success() {
        println!("✅ Identity Announced to Network.");
    } else {
        println!("⚠️  Announcement failed: {}", res.status());
    }
    Ok(())
}
