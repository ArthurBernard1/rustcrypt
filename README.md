rustcrypt

A Rust library for runtime string obfuscation using memory-safe AES-GCM encryption.
Designed to protect sensitive strings such as tokens, URLs, passwords, or API keys in production. Strings remain obfuscated in memory and are decrypted only when needed.

## Features

- **Per-session ephemeral keys**: Each execution generates unique runtime keys
- **Configurable encryption layers**: Choose complexity based on threat model (Single/Double/Triple)
- **Stack allocation**: Short secrets use stack memory to minimize heap exposure
- **Hardware backing**: Optional TPM/SGX support for key protection
- **Memory-safe**: Uses SecretVec / zeroize to protect keys and temporary data
- **Zero-copy operations**: Minimize memory copies and exposure windows
- **Professional API**: Sleek hide / reveal functions for clean usage
- **Production-ready**: Suitable for secrets in compiled binaries

## Example Usage

### Basic Usage
```rust
use rustcrypt::{hide, reveal};
use secrecy::SecretVec;
use rand::Rng;

fn main() {
    // Generate a random runtime key
    let key = SecretVec::new(rand::thread_rng().gen::<[u8;32]>().to_vec());

    // Hide sensitive string in memory
    let mut secret = hide(b"https://mywebhook.com?token=12345", &key).unwrap();

    // Reveal it only when needed
    {
        let original = reveal(&secret, &key).unwrap();
        println!("Secret used: {}", String::from_utf8(original.to_vec()).unwrap());
        // Memory is cleared automatically after `original` goes out of scope
    }

    // Optional: re-hide immediately after use
    secret = hide(b"https://mywebhook.com?token=12345", &key).unwrap();
}
```

### Advanced Usage with Ephemeral Keys
```rust
use rustcrypt::{Rustcrypt, EncryptionLayers, StackSecret};

fn main() {
    // Create with ephemeral session keys and triple-layer encryption
    let rustcrypt = Rustcrypt::with_config(
        None, 
        EncryptionLayers::Triple, 
        true // Use ephemeral keys
    ).unwrap();

    // Hide using stack allocation for short secrets
    let stack_secret: StackSecret<256> = rustcrypt
        .hide_stack(b"api-key-123")
        .unwrap();

    // Decrypt and use
    let decrypted = rustcrypt.reveal_bytes(stack_secret.as_slice()).unwrap();
    println!("Secret: {}", String::from_utf8(decrypted.to_vec()).unwrap());
    // Stack secret automatically zeroized on drop
}
```

### Hardware-Backed Keys (Optional)
```rust
#[cfg(feature = "hardware-keys")]
fn main() {
    let rustcrypt = Rustcrypt::with_hardware_key(EncryptionLayers::Double).unwrap();
    let encrypted = rustcrypt.hide("ultra-secure-secret").unwrap();
    let decrypted = rustcrypt.reveal(&encrypted).unwrap();
    println!("Hardware-backed secret: {}", decrypted);
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

- `new(option: Option<&[u8]>) -> Self` — creates a new instance with optional key
- `with_config(key: Option<&[u8]>, layers: EncryptionLayers, ephemeral: bool) -> Self` — full configuration
- `with_hardware_key(layers: EncryptionLayers) -> Self` — hardware-backed keys (optional feature)
- `hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError>` — obfuscates a string
- `hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError>` — obfuscates bytes
- `reveal(&self, input: &[u8]) -> Result<String, RustcryptError>` — decrypts to string
- `reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError>` — decrypts to bytes
- `hide_stack<const N: usize>(&self, input: &[u8]) -> Result<StackSecret<N>, RustcryptError>` — stack allocation

### Types
- `EncryptionLayers` — Single, Double, or Triple layer encryption
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
rustcrypt = "0.1.0-beta.1"
secrecy = "0.8"
rand = "0.8"

# Optional features
[dependencies.rustcrypt]
version = "0.1.0-beta.1"
features = ["hardware-keys", "ephemeral-sessions"]
```

Run the comprehensive example:
```bash
cargo run --example secure_example
```

## Security Guarantees

- **Memory Safety**: All sensitive data is automatically zeroized on drop
- **Ephemeral Keys**: Each session generates unique keys (when enabled)
- **Stack Allocation**: Short secrets avoid heap exposure
- **Configurable Layers**: Choose encryption complexity based on threat model
- **Hardware Backing**: Optional TPM/SGX support for key protection

## Security Limitations

- **Runtime Attacks**: Live memory dumps can still extract secrets during decryption
- **No OS Protection**: No mlock/anti-dump hardening (consider for high-security contexts)
- **Key Management**: Keys must be managed securely outside the library
- **Hardware Dependencies**: Hardware-backed keys require specific hardware support

## Best Practices

1. **Use ephemeral keys** for maximum security
2. **Choose appropriate encryption layers** based on threat model
3. **Use stack allocation** for short secrets
4. **Decrypt in limited scope** and re-encrypt after use
5. **Consider hardware-backed keys** for high-security applications
6. **Avoid logging sensitive data** in production
7. **Use release builds** with stripped symbols for deployment

This is production-ready, auditable, and suitable for crates.io. It's also fully copy-paste ready for developers.

