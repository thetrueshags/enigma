mod identity;
mod network;
mod ui;
mod vault;

use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use enigma_core::{models::SecretRecord, EnigmaPayload};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "enigma",
    version = "1.1",
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
    /// Encrypt and upload a new secret to the mesh
    Add,
    /// Search the mesh and copy a password to clipboard
    Get {
        /// Search query (matches title, URL, username)
        query: String,
    },
    /// List all secrets from local cache
    List {
        /// Refresh from the network before listing
        #[arg(long)]
        refresh: bool,
    },
    /// Register identity + pull all secrets from the mesh into local cache
    Sync,
    /// Open the vault UI in your browser
    Ui {
        /// Port for the local UI server
        #[arg(long, default_value = "8420")]
        port: u16,
    },
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

    let vp = vault::vault_path(&key_path);

    // 2. For UI mode, skip connection check and go straight to serve
    if let Commands::Ui { port } = cli.command {
        return ui::serve(id, vp, cli.rpc, port).await;
    }

    // 3. Check Connection (except for offline-capable commands)
    let client = reqwest::Client::new();
    let needs_network = !matches!(&cli.command, Commands::List { refresh: false });

    if needs_network && client.get(&cli.rpc).send().await.is_err() {
        eprintln!(
            "❌ {} Could not connect to Axion Node at {}",
            style("ERROR:").red(),
            cli.rpc
        );
        eprintln!("   Ensure the node is running or specify a remote node with --rpc");
        if !matches!(&cli.command, Commands::List { .. }) {
            return Ok(());
        }
    }

    match cli.command {
        Commands::Sync => {
            println!("📡 Announcing encryption key...");
            let res = client
                .post(format!("{}/announce_key", cli.rpc))
                .send()
                .await?;
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            if body.get("error").is_some() {
                eprintln!("❌ Announcement failed: {}", body["error"]);
                return Ok(());
            }
            println!("✅ Key announced.\n");

            println!("📥 Pulling secrets from the mesh...");
            let synced = network::sync_from_network(&client, &cli.rpc, &id, &vp).await?;
            println!("✅ Synced {} secret(s) into local vault.", synced);
        }

        Commands::Add => {
            let title: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Title")
                .interact_text()?;
            let url: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("URL (optional)")
                .allow_empty(true)
                .interact_text()?;
            let user: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Username")
                .interact_text()?;
            let pass = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Password")
                .interact()?;
            let notes: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Notes (optional)")
                .allow_empty(true)
                .interact_text()?;

            println!("🔒 Encrypting...");

            let record = SecretRecord::new(title, &user, &pass, &notes, &url);

            let inner_payload = EnigmaPayload::encrypt(&record, &id.encryption.public)?;
            let inner_bytes = bincode::serialize(&inner_payload)?;

            let body = json!({
                "recipient": id.did,
                "data": hex::encode(inner_bytes)
            });

            let res = client
                .post(format!("{}/publish", cli.rpc))
                .json(&body)
                .send()
                .await?;

            let resp: serde_json::Value = res.json().await.unwrap_or_default();
            if let Some(err) = resp.get("error") {
                eprintln!("❌ Upload failed: {}", err);
                eprintln!("   (Tip: Have you run 'enigma sync' to register your identity?)");
            } else {
                println!("✅ Secret stored on the mesh.");
                let mut vault_data = vault::load(&vp, &id.signing.secret)?;
                vault::upsert(&mut vault_data, record);
                vault::save(&vp, &id.signing.secret, &vault_data)?;
            }
        }

        Commands::Get { query } => {
            println!("🔍 Searching the mesh for '{}'...\n", &query);

            let records = network::fetch_and_decrypt(&client, &cli.rpc, &id).await?;

            // Update local cache
            if !records.is_empty() {
                let mut vault_data = vault::load(&vp, &id.signing.secret)?;
                for r in &records {
                    vault::upsert(&mut vault_data, r.clone());
                }
                vault_data.last_sync = Some(now_secs());
                vault::save(&vp, &id.signing.secret, &vault_data)?;
            }

            let matches = vault::search(&records, &query);

            if matches.is_empty() {
                let vault_data = vault::load(&vp, &id.signing.secret)?;
                let cached = vault::search(&vault_data.records, &query);
                if cached.is_empty() {
                    eprintln!("❌ No secrets matching '{}' found.", query);
                    return Ok(());
                }
                println!("   (from local cache)\n");
                copy_to_clipboard(&cached)?;
            } else {
                copy_to_clipboard(&matches)?;
            }
        }

        Commands::List { refresh } => {
            if refresh {
                println!("📥 Refreshing from the mesh...");
                let synced = network::sync_from_network(&client, &cli.rpc, &id, &vp).await?;
                println!("   {} secret(s) synced.\n", synced);
            }

            let vault_data = vault::load(&vp, &id.signing.secret)?;

            if vault_data.records.is_empty() {
                println!("📭 Vault is empty. Run 'enigma sync' to pull from the mesh.");
                return Ok(());
            }

            for record in &vault_data.records {
                println!("🔹 {}", style(&record.title).bold().green());
                if !record.url.is_empty() {
                    println!("   URL:  {}", style(&record.url).dim());
                }
                println!("   User: {}", record.username);
                println!("   Pass: {}", style("••••••••").dim());
                if !record.notes.is_empty() {
                    println!("   Note: {}", style(&record.notes).italic());
                }
                println!();
            }

            println!("📋 {} secret(s) in vault.", vault_data.records.len());
            if let Some(ts) = vault_data.last_sync {
                let ago = now_secs().saturating_sub(ts);
                let human = if ago < 60 { format!("{}s ago", ago) }
                    else if ago < 3600 { format!("{}m ago", ago / 60) }
                    else { format!("{}h ago", ago / 3600) };
                println!("   Last synced: {}", style(human).dim());
            }
        }

        Commands::Ui { .. } => unreachable!(), // handled above
    }

    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn copy_to_clipboard(matches: &[&SecretRecord]) -> Result<()> {
    let selected = if matches.len() == 1 {
        matches[0]
    } else {
        let items: Vec<String> = matches.iter().map(|r| {
            let url_part = if r.url.is_empty() { String::new() } else { format!(" — {}", r.url) };
            format!("{}{} ({})", r.title, url_part, r.username)
        }).collect();

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Multiple matches — select one")
            .items(&items)
            .default(0)
            .interact()?;

        matches[selection]
    };

    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| anyhow::anyhow!("Clipboard unavailable: {}", e))?;
    clipboard.set_text(&selected.password)
        .map_err(|e| anyhow::anyhow!("Failed to copy: {}", e))?;

    println!("🔹 {}", style(&selected.title).bold().green());
    if !selected.url.is_empty() {
        println!("   URL:  {}", selected.url);
    }
    println!("   User: {}", selected.username);
    println!("   ✅ Password copied to clipboard.");
    println!("   ⏱️  Auto-clearing in 30 seconds...");

    let password = selected.password.clone();
    std::thread::sleep(std::time::Duration::from_secs(30));
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.get_text().map(|t| t == password).unwrap_or(false) {
            let _ = cb.set_text("");
            println!("   🧹 Clipboard cleared.");
        }
    }

    Ok(())
}
