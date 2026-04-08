# Enigma

Quantum-safe secret vault built on [Axion](https://github.com/thetrueshags/axion). Your secrets live on the Axion mesh — sharded across nodes, double-encrypted with post-quantum cryptography. If your device is wiped, you recover everything with just your identity file.

## How it works

```
You  -->  Enigma (Kyber + AES)  -->  Axion (Kyber + AES)  -->  Mesh
         client-side encryption      transport encryption      sharded storage
```

Every secret is encrypted **twice** before it touches the network:

1. **Layer 1 (Enigma)** — Kyber-1024 KEM + AES-256-GCM. Only your encryption key can decrypt.
2. **Layer 2 (Axion)** — The Axion node wraps the already-encrypted payload in another Kyber + AES layer for transport.

Both layers use NIST-standardized post-quantum algorithms. Even a quantum computer can't read your secrets.

## Install

```sh
cargo install --path crates/enigma-cli
```

Requires a running [Axion node](https://github.com/thetrueshags/axion):

```sh
cd ../axion
cargo run -- init
cargo run -- start
```

## Quick start

```sh
# First time: register your identity on the network
enigma sync

# Store a secret
enigma add

# Search and copy a password to clipboard
enigma get github

# Open the vault UI in your browser
enigma ui

# List everything in your local vault
enigma list
```

## Commands

### `enigma ui`

Opens a web-based vault UI at `http://127.0.0.1:8420`. Dark theme, search, copy-to-clipboard, add secrets, sync from the mesh — all from your browser.

```sh
enigma ui              # default port 8420
enigma ui --port 9000  # custom port
```

### `enigma get <query>`

Searches the mesh for secrets matching your query (title, URL, or username). Copies the password to clipboard and auto-clears after 30 seconds.

```sh
enigma get github       # copies GitHub password
enigma get steam        # copies Steam password
enigma get "visa 1234"  # copies card number
```

If multiple secrets match, you'll get an interactive selection prompt.

### `enigma add`

Interactive prompts to store a new secret on the mesh.

```
$ enigma add
Title: GitHub
URL (optional): https://github.com
Username: user@example.com
Password: ****
Notes (optional): 2FA enabled
```

The secret is encrypted client-side, published to the Axion mesh, and cached locally.

### `enigma list [--refresh]`

Lists all secrets from the local vault cache. Passwords are masked — use `get` to copy.

```sh
enigma list             # read from local cache (fast, works offline)
enigma list --refresh   # pull from mesh first, then list
```

### `enigma sync`

Announces your encryption key to the network and pulls all your secrets from the mesh into the local cache. Run this:

- On first setup
- On a new device after restoring your identity
- Periodically to pick up secrets added from other devices

## Recovery

Your secrets are stored on the Axion mesh, not just on your device. To recover after a device loss:

1. Get your `identity.json` file (keep a backup somewhere safe)
2. Install Enigma on the new device
3. Copy `identity.json` to the config directory:
   - **Windows:** `%APPDATA%\axion\enigma\`
   - **macOS:** `~/Library/Application Support/axion/enigma/`
   - **Linux:** `~/.config/axion/enigma/`
4. Run `enigma sync` — all secrets are pulled from the mesh
5. Run `enigma ui` or `enigma get` — back in business

## Architecture

```
enigma-cli          CLI + web UI + vault + network
  enigma-core       encryption/decryption (Kyber + AES)
    axion-core      block types, validation, storage
    axion-crypto    Dilithium-5 signing, Kyber-1024 KEM, AES-256-GCM
```

- **enigma-core** — `EnigmaPayload::encrypt/decrypt` handles client-side hybrid encryption. `SecretRecord` is the plaintext model (title, URL, username, password, notes).
- **enigma-cli** — CLI commands, web UI server, local encrypted vault cache (`vault.enc`), network sync logic.
- **axion-core / axion-crypto** — L1 primitives. Enigma depends on Axion, never the reverse.

### Local vault

`vault.enc` is an AES-256-GCM encrypted cache that sits next to your `identity.json`. The encryption key is derived from your signing secret with a domain separator (`SHA3-256("enigma-vault-v1" || signing_secret)`). The vault is a speed cache — the mesh is the source of truth.

## Security

| Property | How |
|---|---|
| Post-quantum encryption | Kyber-1024 (NIST ML-KEM Level 5) + AES-256-GCM |
| Post-quantum signatures | Dilithium-5 (NIST ML-DSA Level 5) via Axion L1 |
| Double encryption | Client-side (Enigma) + transport (Axion) |
| Authenticated encryption | AES-256-GCM provides confidentiality + integrity |
| Sybil defense | Identity registration requires 16-bit PoW |
| Data availability | Secrets sharded across Axion mesh nodes |
| Clipboard safety | Auto-clears after 30 seconds |
| Vault cache | AES-256-GCM with domain-separated key derivation |
| Backward compatibility | Old secrets (pre-URL field) decrypt via legacy fallback |

## License

MIT
