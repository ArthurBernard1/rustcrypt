# RustCrypt

<div align="center">

# **RustCrypt** - Advanced Runtime String Obfuscation

[![Crates.io](https://img.shields.io/crates/v/rustcrypt.svg)](https://crates.io/crates/rustcrypt)
[![Documentation](https://docs.rs/rustcrypt/badge.svg)](https://docs.rs/rustcrypt)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-military%20grade-red.svg)](https://github.com/ArthurBernard1/rustcrypt)

*Protect your secrets with advanced encryption layers*

</div>

A production-ready Rust library for runtime string obfuscation using memory-safe AES-GCM encryption. Designed to protect sensitive strings such as API keys, tokens, passwords, and webhook URLs in production environments. Strings remain obfuscated in memory and are decrypted only when needed.

## Key Features

### Advanced Encryption
- **Multi-layer encryption**: Single, Double, Triple, and Military-grade layers
- **Per-session ephemeral keys**: Each execution generates unique runtime keys
- **Bit-level key scattering**: Keys fragmented across random memory positions
- **Control flow obfuscation**: Junk instructions to confuse reverse engineering
- **Key derivation**: HKDF-derived subkeys with per-message salts; additional time-based derivation used in obfuscated keys

### Memory Security
- **Stack allocation**: Short secrets use stack memory to minimize heap exposure
- **Automatic zeroization**: All sensitive data cleared on drop using `zeroize`
- **Zero-copy operations**: Minimize memory copies and exposure windows

### Developer Experience
- **Clean API**: Simple `hide()` and `reveal()` functions
- **Production-ready**: Battle-tested for crates.io deployment
- **Comprehensive documentation**: Full examples and API reference
- **Easy integration**: Drop-in replacement for plain strings

## Usage Examples

### Securing API Keys
```rust
use rustcrypt::{hide, reveal};
use secrecy::SecretVec;
use rand::Rng;

fn main() {
    let key = SecretVec::new(rand::thread_rng().gen::<[u8;32]>().to_vec());

    let mut api_key = hide(b"sk-1234567890abcdef1234567890abcdef", &key).unwrap();

    {
        let decrypted_key = reveal(&api_key, &key).unwrap();
        println!("API Key: {}", String::from_utf8(decrypted_key.to_vec()).unwrap());
    }

    api_key = hide(b"sk-1234567890abcdef1234567890abcdef", &key).unwrap();
}
```

### Database Credentials Protection
```rust
use rustcrypt::{Rustcrypt, EncryptionLayers, StackSecret};

fn main() {
    let rustcrypt = Rustcrypt::with_config(
        None, 
        EncryptionLayers::Military, 
        true
    ).unwrap();

    let db_password: StackSecret<256> = rustcrypt
        .hide_stack(b"SuperSecretDBPassword123!")
        .unwrap();

    let decrypted = rustcrypt.reveal_bytes(db_password.as_slice()).unwrap();
    println!("Connecting to database with password: {}", 
             String::from_utf8(decrypted.to_vec()).unwrap());
}
```

### Webhook URLs and Tokens
```rust
use rustcrypt::{hide_layered, reveal_layered, EncryptionLayers};
use secrecy::SecretVec;
use rand::Rng;

fn main() {
    let key = SecretVec::new(rand::thread_rng().gen::<[u8;32]>().to_vec());
    
    let webhook_url = "https://thiswouldbeyourtypicalapiserver/webhook?token=abc123xyz789&user=admin";
    let encrypted_webhook = hide_layered(webhook_url.as_bytes(), &key, EncryptionLayers::Triple).unwrap();
    
    {
        let decrypted_webhook = reveal_layered(&encrypted_webhook, &key, EncryptionLayers::Triple).unwrap();
        let url = String::from_utf8(decrypted_webhook.to_vec()).unwrap();
        println!("Sending data to: {}", url);
    }
}
```

### Session Cookies and JWT Tokens
```rust
use rustcrypt::{Rustcrypt, EncryptionLayers};

fn main() {
    let rustcrypt = Rustcrypt::new(None).unwrap();
    
    // Hide session cookie
    let session_cookie = "session_id=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    let encrypted_cookie = rustcrypt.hide(session_cookie).unwrap();
    
    // Use the cookie
    let decrypted_cookie = rustcrypt.reveal(&encrypted_cookie).unwrap();
    println!("Session Cookie: {}", decrypted_cookie);
}
```


## API Reference

### Core Functions
- `hide(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError>` — Basic encryption
- `reveal(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError>` — Basic decryption
- `hide_layered(input: &[u8], key: &SecretVec<u8>, layers: EncryptionLayers) -> Result<Vec<u8>, RustcryptError>` — Configurable encryption
- `reveal_layered(input: &[u8], key: &SecretVec<u8>, layers: EncryptionLayers) -> Result<Zeroizing<Vec<u8>>, RustcryptError>` — Configurable decryption

### Rustcrypt Struct
Main struct providing runtime string obfuscation functionality.

- `new(option: Option<&[u8]>) -> Result<Self, RustcryptError>` — creates a new instance with optional key
- `with_config(key: Option<&[u8]>, layers: EncryptionLayers, ephemeral: bool) -> Result<Self, RustcryptError>` — full configuration
- `hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError>` — obfuscates a string
- `hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError>` — obfuscates bytes
- `reveal(&self, input: &[u8]) -> Result<String, RustcryptError>` — decrypts to string
- `reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError>` — decrypts to bytes
- `hide_stack<const N: usize>(&self, input: &[u8]) -> Result<StackSecret<N>, RustcryptError>` — stack allocation

### Types
- `EncryptionLayers` — Single, Double, Triple, or Military layer encryption
- `StackSecret<N>` — Stack-allocated secret with automatic zeroization
- `RustcryptError` — Error types for all operations

### Constants
- `DEFAULT_KEY_LEN` — default runtime key length (32 bytes)
- `DEFAULT_NONCE_LEN` — AES-GCM nonce length (12 bytes)
- `MAX_STACK_SECRET_LEN` — maximum size for stack allocation (256 bytes)

## Quick Start

Add rustcrypt to your Cargo.toml:

```toml
[dependencies]
rustcrypt = "0.1.0-beta.2"
secrecy = "0.8"
rand = "0.8"
```

## Security Guarantees

- **Memory Safety**: All sensitive data is automatically zeroized on drop
- **Ephemeral Keys**: Each session generates unique keys (when enabled)
- **Stack Allocation**: Short secrets avoid heap exposure
- **Configurable Layers**: Choose encryption complexity based on threat model

RustCrypt is production-ready, thoroughly auditable, and ready for crates.io deployment. All examples are fully functional and ready for immediate use in your projects.