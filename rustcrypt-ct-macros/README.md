# rustcrypt-ct-macros

Procedural macros for rustcrypt providing compile-time obfuscation helpers:

- obf_lit!("text") -> String
- obf_lit_bytes!(b"bytes") -> Vec<u8>
- obf_lit_cstr!("nul\0terminated") -> Vec<u8> (includes trailing nul)
- obf_lit_array!(b"raw") -> ([u8; N], [u8; N])

These macros emit obfuscated arrays and perform XOR at runtime to recover data with minimal overhead.

## Usage

Add to your Cargo.toml:

```toml
[dependencies]
rustcrypt = "0.2.0-beta.1"
```

Then in code:

```rust
use rustcrypt::{obf_lit, obf_lit_bytes, obf_lit_cstr, obf_lit_array};

fn main() {
    let s = obf_lit!("hello");
    let b = obf_lit_bytes!(b"bytes");
    let c = obf_lit_cstr!("zero\0term");
    let (obf, key) = obf_lit_array!(b"raw");
    let _ = (s, b, c, obf, key);
}
```

License: MIT
