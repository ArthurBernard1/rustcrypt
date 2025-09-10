# rustcrypt

[![crates.io](https://img.shields.io/crates/v/rustcrypt.svg)](https://crates.io/crates/rustcrypt)
[![docs.rs](https://docs.rs/rustcrypt/badge.svg)](https://docs.rs/rustcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Macro-first encryption and obfuscation library for Rust.
Protect your source code from reverse engineering with compile-time string obfuscation, automatic struct encryption, and control flow obfuscation powered by procedural macros.

---

## Features

- Compile-time string obfuscation
- Automatic struct encryption via derive
- Control flow obfuscation
- Multiple encryption layers
- Zero runtime dependencies
- Rustfuscator-inspired API

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rustcrypt = "0.3.0-beta.1"
```

### Basic Usage

```rust
use rustcrypt::{obfuscate_string, obfuscate_flow, Obfuscate};

fn main() {
    let secret = obfuscate_string!("my secret password");
    obfuscate_flow!();
    #[derive(Obfuscate)]
    struct UserData {
        name: String,
        age: u32,
    }
    let user = ObfuscatedUserData::new_clear("Alice", 30);
    let clear_data = user.get_clear();
}
```

## API Reference

### String Obfuscation Macros

#### `obfuscate_string!`

Obfuscates a string literal at compile time.

```rust
use rustcrypt::obfuscate_string;

let secret = obfuscate_string!("sensitive data");
```

#### `obfuscate_bytes!`

Obfuscates a byte string literal at compile time.

```rust
use rustcrypt::obfuscate_bytes;

let secret_bytes = obfuscate_bytes!(b"binary data");
```

### Control Flow Obfuscation

#### `obfuscate_flow!`

Inserts opaque control flow to make reverse engineering more difficult.

```rust
use rustcrypt::obfuscate_flow;

obfuscate_flow!();
obfuscate_flow!();
```

### Automatic Struct Encryption

#### `#[derive(Obfuscate)]`

Automatically generates encrypted versions of structs.

```rust
use rustcrypt::Obfuscate;

#[derive(Obfuscate)]
struct Config {
    api_key: String,
    database_url: String,
    timeout: u32,
}

let config = ObfuscatedConfig::new_clear(
    "sk-1234567890abcdef",
    "postgresql://localhost:5432/mydb", 
    30
);

let clear_config = config.get_clear();
```

**Supported field types:**
- `String` / `&str`
- `u32`, `u64`
- `i32`, `i64` 
- `bool`

### Legacy Compile-Time Macros

The original compile-time macros are still available:

```rust
use rustcrypt::{obf_lit, obf_lit_bytes, obf_lit_cstr, obf_lit_array};

    let s = obf_lit!("hello");
    let b = obf_lit_bytes!(b"bytes");
    let c = obf_lit_cstr!("zero\0term");
    let (obf, key) = obf_lit_array!(b"raw");
```

## Architecture

Rustcrypt is built as a workspace with specialized crates:

```
rustcrypt/
├── rustcrypt-core/        # Core encryption and obfuscation functionality
├── rustcrypt-macros/      # Function-like procedural macros
├── rustcrypt-derive/      # Derive macros for automatic struct encryption
├── rustcrypt-ct-macros/   # Compile-time literal obfuscation macros
└── examples/              # Usage examples
```

### How It Works

1. Compile-time encryption
2. Runtime decryption
3. Zero runtime cost
4. Memory safety

## Examples

### Basic String Obfuscation

```rust
use rustcrypt::obfuscate_string;

fn main() {
    let password = obfuscate_string!("admin123");
    let api_key = obfuscate_string!("sk-1234567890abcdef");
}
```

### Complex Struct Encryption

```rust
use rustcrypt::Obfuscate;

#[derive(Obfuscate)]
struct DatabaseConfig {
    host: String,
    port: u32,
    username: String,
    password: String,
    ssl_enabled: bool,
}

#[derive(Obfuscate)]
struct AppConfig {
    app_name: String,
    version: String,
    database: String,
}

fn main() {
    let db_config = ObfuscatedDatabaseConfig::new_clear(
        "localhost",
        5432,
        "admin",
        "secret_password",
        true
    );
    
    let app_config = ObfuscatedAppConfig::new_clear("MyApp", "1.0.0", "db");
}
```

### Layered Protection

```rust
use rustcrypt::{obfuscate_string, obfuscate_flow, Obfuscate};

fn main() {
    obfuscate_flow!();
    
    let sensitive_data = obfuscate_string!("credit_card=4111111111111111");
    
    #[derive(Obfuscate)]
    struct PaymentInfo {
        card_number: String,
        cvv: String,
    }
    
    let payment = ObfuscatedPaymentInfo::new_clear(&sensitive_data, "123");
    
    obfuscate_flow!();
    let _clear_payment = payment.get_clear();
}
```

## Advanced Usage

### Custom Encryption Layers

```rust
use rustcrypt_core::{Rustcrypt, EncryptionLayers};

let crypto = Rustcrypt::with_config(
    Some(b"your-32-byte-key-here-123456789012"),
    EncryptionLayers::Military,
    false
)?;

let encrypted = crypto.hide("sensitive data")?;
let decrypted = crypto.reveal(&encrypted)?;
```

### Stack-Based Secrets

```rust
use rustcrypt_core::{Rustcrypt, StackSecret};

let crypto = Rustcrypt::new(None)?;
let stack_secret: StackSecret<256> = crypto.hide_stack(b"small secret")?;
```

### Additional Macros

```rust
use rustcrypt::{
    obfuscate_bytes, obfuscate_cstr, obfuscate_bytes_array, obfuscate_const_bytes,
    obfuscate_flow_heavy, obfuscate_branch, obfuscate_select, obfuscate_loop, obfuscate_fn,
};

let _b = obfuscate_bytes!(b"data");
let _c = obfuscate_cstr!("z");
let _arr = obfuscate_bytes_array!([1,2,3]);
let _cb = obfuscate_const_bytes!(b"const");
obfuscate_flow_heavy!();
let _x = if obfuscate_branch!(1 + 1 == 2) { 1 } else { 0 };
let _y: u32 = obfuscate_select!((true, || { 10u32 }, || { 20u32 }));
obfuscate_loop!((3, { let _t = i; std::hint::black_box(_t); }));

#[obfuscate_fn]
fn f(n: u64) -> u64 { n.wrapping_mul(3) }
```

## Security Considerations

- **Not a silver bullet**: Obfuscation increases complexity but doesn't guarantee security
- **Combine with other techniques**: Use with binary stripping, anti-debugging, etc.
- **Key management**: Ensure proper key derivation and storage
- **Memory safety**: All secrets are zeroized when dropped

## Performance

- **Zero runtime overhead**: All obfuscation happens at compile time
- **Minimal binary size increase**: Only encrypted data is added
- **Fast decryption**: Optimized for runtime performance
- **Memory efficient**: Automatic cleanup of sensitive data

## Requirements

- Rust 1.70+
- No external dependencies for basic usage
- Optional features for advanced functionality

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by rustfuscator
- Built on top of proven cryptographic libraries
- Community feedback and contributions

---