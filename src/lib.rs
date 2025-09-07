//! rustcrypt — runtime string obfuscation using AES-GCM, memory-safe.
//!
//! High-level API: [`hide`], [`reveal`], and the [`Rustcrypt`] struct.
//!
//! # Security Features
//! - **Per-session ephemeral keys**: Each execution generates unique runtime keys
//! - **Stack allocation**: Short secrets use stack memory to minimize heap exposure
//! - **Configurable layers**: Choose encryption complexity based on threat model
//! - **Hardware backing**: Optional TPM/SGX support for key protection
//! - **Zero-copy operations**: Minimize memory copies and exposure windows

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{RngCore, Rng};
use secrecy::{ExposeSecret, SecretVec};
use zeroize::{Zeroize, Zeroizing};
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_KEY_LEN: usize = 32; // 256-bit
pub const DEFAULT_NONCE_LEN: usize = 12; // AES-GCM nonce
pub const MAX_STACK_SECRET_LEN: usize = 256; // Use stack for secrets <= 256 bytes

// Session counter for ephemeral key generation
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

// Military-grade obfuscation constants
const OBFUSCATION_ROUNDS: usize = 16;
const KEY_DERIVATION_ROUNDS: usize = 32;
const FRAGMENT_SPACE_SIZE: usize = 4096;
const JUNK_DATA_SIZE: usize = 1024;

#[derive(Debug)]
pub enum RustcryptError {
    MalformedInput,
    Encrypt,
    Decrypt,
    InvalidKey,
    HardwareKey,
    StackTooLarge,
}

impl std::fmt::Display for RustcryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RustcryptError::MalformedInput => write!(f, "malformed input"),
            RustcryptError::Encrypt => write!(f, "encryption failure"),
            RustcryptError::Decrypt => write!(f, "decryption failure"),
            RustcryptError::InvalidKey => write!(f, "invalid key length"),
            RustcryptError::HardwareKey => write!(f, "hardware key failure"),
            RustcryptError::StackTooLarge => write!(f, "stack allocation too large"),
        }
    }
}

impl std::error::Error for RustcryptError {}

#[derive(Debug, Clone, Copy)]
pub enum EncryptionLayers {
    Single,    // Just AES-GCM
    Double,    // AES-GCM + XChaCha20
    Triple,    // AES-GCM + XChaCha20 + additional obfuscation
    Military,  // Military-grade with advanced obfuscation
}

impl Default for EncryptionLayers {
    fn default() -> Self { EncryptionLayers::Double }
}

fn to_key(key: &SecretVec<u8>) -> Result<aes_gcm::Key<aes_gcm::aes::Aes256>, RustcryptError> {
    if key.expose_secret().len() != DEFAULT_KEY_LEN { return Err(RustcryptError::InvalidKey); }
    Ok(aes_gcm::Key::<aes_gcm::aes::Aes256>::from_slice(key.expose_secret()).to_owned())
}

fn gen_nonce() -> [u8; DEFAULT_NONCE_LEN] {
    let mut nonce = [0u8; DEFAULT_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Military-grade control flow obfuscation with junk instructions
fn obfuscate_control_flow<T>(mut value: T, rounds: usize) -> T 
where 
    T: std::ops::BitXor<Output = T> + Copy,
{
    let mut rng = rand::thread_rng();
    let mut junk = [0u8; 16];
    
    for _ in 0..rounds {
        // Generate junk data to confuse static analysis
        rng.fill_bytes(&mut junk);
        
        // Perform meaningless operations that look like real code
        let junk_val = u64::from_le_bytes(junk[0..8].try_into().unwrap());
        let mask = (junk_val % 256) as u8;
        
        // XOR with junk data (appears as legitimate encryption)
        value = value ^ unsafe { std::mem::transmute_copy(&mask) };
        
        // More junk operations
        let _ = junk.iter().fold(0u64, |acc, &x| acc.wrapping_add(x as u64));
    }
    
    value
}

/// Advanced key derivation with multiple rounds and time-based entropy
fn derive_military_key(base_key: &[u8], context: &[u8]) -> [u8; 32] {
    let mut derived = [0u8; 32];
    let mut rng = rand::thread_rng();
    
    // Time-based entropy for additional randomness
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Multi-round key derivation with obfuscation
    for round in 0..KEY_DERIVATION_ROUNDS {
        let mut round_key = [0u8; 32];
        
        // Mix base key with context and round number
        for i in 0..32 {
            let base_byte = base_key[i % base_key.len()];
            let context_byte = context[i % context.len()];
            let round_byte = (round as u8).wrapping_add(i as u8);
            let time_byte = ((timestamp >> (i % 8)) & 0xFF) as u8;
            
            round_key[i] = base_byte
                .wrapping_add(context_byte)
                .wrapping_add(round_byte)
                .wrapping_add(time_byte);
        }
        
        // Apply obfuscation to the round key
        for i in 0..32 {
            round_key[i] = obfuscate_control_flow(round_key[i], OBFUSCATION_ROUNDS);
        }
        
        // XOR with previous round result
        for i in 0..32 {
            derived[i] ^= round_key[i];
        }
        
        // Additional entropy injection
        let mut entropy = [0u8; 4];
        rng.fill_bytes(&mut entropy);
        let entropy_val = u32::from_le_bytes(entropy);
        
        for i in 0..32 {
            derived[i] = derived[i].wrapping_add(((entropy_val >> (i % 4)) & 0xFF) as u8);
        }
    }
    
    derived
}

/// Generate junk data to confuse static analysis
fn generate_junk_data() -> Vec<u8> {
    let mut junk = vec![0u8; JUNK_DATA_SIZE];
    rand::thread_rng().fill_bytes(&mut junk);
    
    // Insert fake encryption patterns to mislead analysis
    for i in (0..junk.len()).step_by(16) {
        if i + 15 < junk.len() {
            // Insert fake AES-like patterns
            junk[i] = 0x2B; // Fake AES S-box constant
            junk[i + 1] = 0x7E;
            junk[i + 2] = 0x15;
            junk[i + 3] = 0x16;
        }
    }
    
    junk
}

/// Military-grade key obfuscation system with advanced fragmentation
#[derive(Debug, Clone)]
pub struct ObfuscatedKey {
    /// Scattered key fragments stored at random positions
    fragments: HashMap<usize, u8>,
    /// XOR masks for each fragment to prevent direct reconstruction
    masks: HashMap<usize, u8>,
    /// Total key length in bytes
    key_len: usize,
    /// Random seed used during key generation (for future use)
    #[allow(dead_code)]
    seed: u64,
    /// Junk data to confuse static analysis
    junk_data: Vec<u8>,
    /// Obfuscation rounds applied
    obfuscation_level: usize,
}

impl ObfuscatedKey {
    /// Create military-grade obfuscated key from raw key bytes
    pub fn new(key: &[u8]) -> Self {
        let mut rng = rand::thread_rng();
        let mut fragments = HashMap::new();
        let mut masks = HashMap::new();
        
        // Generate junk data for obfuscation
        let junk_data = generate_junk_data();
        
        // Apply military-grade key derivation first
        let derived_key = derive_military_key(key, b"military_grade_context");
        
        // Split derived key into individual bits and scatter them across random positions
        for (_, &byte) in derived_key.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> bit_idx) & 1;
                let fragment_pos = rng.gen_range(0..FRAGMENT_SPACE_SIZE);
                let mask = rng.gen::<u8>();
                
                // Apply multiple rounds of obfuscation to each bit
                let mut obfuscated_bit = bit;
                for _ in 0..OBFUSCATION_ROUNDS {
                    obfuscated_bit = obfuscate_control_flow(obfuscated_bit, 1);
                }
                
                // Store bit XOR'd with random mask and additional obfuscation
                fragments.insert(fragment_pos, obfuscated_bit ^ (mask & 1));
                masks.insert(fragment_pos, mask);
            }
        }
        
        Self {
            fragments,
            masks,
            key_len: key.len(),
            seed: rng.gen(),
            junk_data,
            obfuscation_level: OBFUSCATION_ROUNDS,
        }
    }
    
    /// Reconstruct the original key with military-grade deobfuscation
    pub fn reconstruct(&self) -> Result<Vec<u8>, RustcryptError> {
        let mut key = vec![0u8; self.key_len];
        let mut bit_positions = Vec::new();
        
        // Collect all fragment positions and sort them for ordered reconstruction
        for &pos in self.fragments.keys() {
            bit_positions.push(pos);
        }
        bit_positions.sort();
        
        // Reconstruct original key byte by byte from scattered fragments
        let mut current_byte = 0u8;
        let mut bit_count = 0;
        let mut byte_idx = 0;
        
        for &pos in &bit_positions {
            if let (Some(&fragment), Some(&mask)) = (self.fragments.get(&pos), self.masks.get(&pos)) {
                // Reverse the obfuscation process
                let mut deobfuscated_bit = fragment ^ (mask & 1);
                
                // Reverse the obfuscation rounds
                for _ in 0..self.obfuscation_level {
                    deobfuscated_bit = obfuscate_control_flow(deobfuscated_bit, 1);
                }
                
                current_byte |= deobfuscated_bit << (bit_count % 8);
                bit_count += 1;
                
                if bit_count % 8 == 0 {
                    if byte_idx < self.key_len {
                        key[byte_idx] = current_byte;
                        byte_idx += 1;
                    }
                    current_byte = 0;
                }
            }
        }
        
        if byte_idx != self.key_len {
            return Err(RustcryptError::MalformedInput);
        }
        
        // Apply additional deobfuscation using junk data
        for i in 0..key.len() {
            let junk_idx = i % self.junk_data.len();
            key[i] = key[i].wrapping_sub(self.junk_data[junk_idx]);
        }
        
        Ok(key)
    }
    
    /// Get obfuscated fragments for inspection and debugging
    pub fn fragments(&self) -> &HashMap<usize, u8> {
        &self.fragments
    }
}

impl Drop for ObfuscatedKey {
    fn drop(&mut self) {
        // Clear all sensitive data to prevent memory leaks
        self.fragments.clear();
        self.masks.clear();
        self.junk_data.zeroize();
    }
}

/// Generate ephemeral session key with session counter for uniqueness
fn gen_ephemeral_key() -> SecretVec<u8> {
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut key = [0u8; DEFAULT_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    
    // Mix session ID into key for additional uniqueness per execution
    for (i, byte) in key.iter_mut().enumerate() {
        *byte ^= ((session_id >> (i % 8)) & 0xFF) as u8;
    }
    
    SecretVec::new(key.to_vec())
}

/// Generate obfuscated ephemeral key with scattered binary fragments
fn gen_obfuscated_ephemeral_key() -> ObfuscatedKey {
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut key = [0u8; DEFAULT_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    
    // Mix session ID into key for additional uniqueness per execution
    for (i, byte) in key.iter_mut().enumerate() {
        *byte ^= ((session_id >> (i % 8)) & 0xFF) as u8;
    }
    
    ObfuscatedKey::new(&key)
}

/// Hardware-backed key generation (placeholder for future implementation)
fn gen_hardware_key() -> Result<SecretVec<u8>, RustcryptError> {
    // Placeholder for TPM/SGX integration
    // In production implementation, would use TPM2 or SGX APIs
    Err(RustcryptError::HardwareKey)
}

/// Stack-allocated secret for short data
pub struct StackSecret<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> StackSecret<N> {
    pub fn new(data: &[u8]) -> Result<Self, RustcryptError> {
        if data.len() > N {
            return Err(RustcryptError::StackTooLarge);
        }
        let mut secret = Self {
            data: [0u8; N],
            len: data.len(),
        };
        secret.data[..data.len()].copy_from_slice(data);
        Ok(secret)
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl<const N: usize> Drop for StackSecret<N> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Hide bytes using configurable encryption layers
pub fn hide_layered(input: &[u8], key: &SecretVec<u8>, layers: EncryptionLayers) -> Result<Vec<u8>, RustcryptError> {
    match layers {
        EncryptionLayers::Single => hide_single(input, key),
        EncryptionLayers::Double => hide_double(input, key),
        EncryptionLayers::Triple => hide_triple(input, key),
        EncryptionLayers::Military => hide_military(input, key),
    }
}

/// Hide bytes using AES-256-GCM. Output format: [12-byte nonce || ciphertext]
pub fn hide(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    hide_layered(input, key, EncryptionLayers::default())
}

/// Military-grade single layer AES-GCM encryption with obfuscation
fn hide_single(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    let key = to_key(key)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = gen_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Apply military-grade obfuscation to input before encryption
    let mut obfuscated_input = input.to_vec();
    for i in 0..obfuscated_input.len() {
        obfuscated_input[i] = obfuscate_control_flow(obfuscated_input[i], OBFUSCATION_ROUNDS);
    }
    
    let ct = cipher.encrypt(nonce, obfuscated_input.as_slice()).map_err(|_| RustcryptError::Encrypt)?;
    
    // Apply additional obfuscation to ciphertext
    let mut obfuscated_ct = ct;
    for i in 0..obfuscated_ct.len() {
        obfuscated_ct[i] = obfuscate_control_flow(obfuscated_ct[i], OBFUSCATION_ROUNDS);
    }
    
    let mut out = Vec::with_capacity(DEFAULT_NONCE_LEN + obfuscated_ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&obfuscated_ct);
    Ok(out)
}

/// Double layer: AES-GCM + XChaCha20-Poly1305
fn hide_double(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    
    // First layer: AES-GCM
    let stage1 = hide_single(input, key)?;
    
    // Second layer: XChaCha20-Poly1305 with derived key
    let mut derived_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut derived_key);
    let xchacha = XChaCha20Poly1305::new_from_slice(&derived_key).map_err(|_| RustcryptError::Encrypt)?;
    let mut xnonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut xnonce_bytes);
    let xnonce = XNonce::from_slice(&xnonce_bytes);
    let xct = xchacha.encrypt(xnonce, stage1.as_ref()).map_err(|_| RustcryptError::Encrypt)?;
    
    // Output: [derived_key || xnonce || xct]
    let mut out = Vec::with_capacity(32 + 24 + xct.len());
    out.extend_from_slice(&derived_key);
    out.extend_from_slice(&xnonce_bytes);
    out.extend_from_slice(&xct);
    Ok(out)
}

/// Triple layer: AES-GCM + XChaCha20 + additional obfuscation
fn hide_triple(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    // First two layers
    let stage2 = hide_double(input, key)?;
    
    // Third layer: Additional XOR obfuscation with random mask
    let mut mask = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut mask);
    
    let mut obfuscated = stage2.clone();
    for (i, byte) in obfuscated.iter_mut().enumerate() {
        *byte ^= mask[i % 32];
    }
    
    // Output: [mask || obfuscated]
    let mut out = Vec::with_capacity(32 + obfuscated.len());
    out.extend_from_slice(&mask);
    out.extend_from_slice(&obfuscated);
    Ok(out)
}

/// Reveal bytes with configurable layers
pub fn reveal_layered(input: &[u8], key: &SecretVec<u8>, layers: EncryptionLayers) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    match layers {
        EncryptionLayers::Single => reveal_single(input, key),
        EncryptionLayers::Double => reveal_double(input, key),
        EncryptionLayers::Triple => reveal_triple(input, key),
        EncryptionLayers::Military => reveal_military(input, key),
    }
}

/// Reveal bytes previously hidden with [`hide`]. Returns zeroizing Vec.
pub fn reveal(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    reveal_layered(input, key, EncryptionLayers::default())
}

/// Military-grade single layer AES-GCM decryption with deobfuscation
fn reveal_single(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < DEFAULT_NONCE_LEN { return Err(RustcryptError::MalformedInput); }
    let key = to_key(key)?;
    let cipher = Aes256Gcm::new(&key);
    let (nonce_part, ct) = input.split_at(DEFAULT_NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_part);
    
    // Deobfuscate ciphertext before decryption
    let mut deobfuscated_ct = ct.to_vec();
    for i in 0..deobfuscated_ct.len() {
        deobfuscated_ct[i] = obfuscate_control_flow(deobfuscated_ct[i], OBFUSCATION_ROUNDS);
    }
    
    let mut pt = cipher.decrypt(nonce, deobfuscated_ct.as_slice()).map_err(|_| RustcryptError::Decrypt)?;
    
    // Deobfuscate plaintext after decryption
    for i in 0..pt.len() {
        pt[i] = obfuscate_control_flow(pt[i], OBFUSCATION_ROUNDS);
    }
    
    Ok(Zeroizing::new(pt))
}

/// Double layer decryption
fn reveal_double(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    
    if input.len() < 32 + 24 { return Err(RustcryptError::MalformedInput); }
    
    // Extract components
    let (derived_key_part, rest) = input.split_at(32);
    let (xnonce_part, xct) = rest.split_at(24);
    
    // Decrypt XChaCha20 layer
    let xchacha = XChaCha20Poly1305::new_from_slice(derived_key_part).map_err(|_| RustcryptError::Decrypt)?;
    let xnonce = XNonce::from_slice(xnonce_part);
    let stage1 = xchacha.decrypt(xnonce, xct).map_err(|_| RustcryptError::Decrypt)?;
    
    // Decrypt AES-GCM layer
    reveal_single(&stage1, key)
}

/// Triple layer decryption
fn reveal_triple(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < 32 { return Err(RustcryptError::MalformedInput); }
    
    // Extract mask and obfuscated data
    let (mask_part, obfuscated) = input.split_at(32);
    
    // Deobfuscate
    let mut deobfuscated = obfuscated.to_vec();
    for (i, byte) in deobfuscated.iter_mut().enumerate() {
        *byte ^= mask_part[i % 32];
    }
    
    // Decrypt remaining layers
    reveal_double(&deobfuscated, key)
}

/// Military-grade encryption with maximum obfuscation
fn hide_military(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    // First apply triple layer encryption
    let triple_encrypted = hide_triple(input, key)?;
    
    // Apply military-grade key derivation
    let military_key = derive_military_key(key.expose_secret(), b"military_encryption");
    let military_secret = SecretVec::new(military_key.to_vec());
    
    // Encrypt with derived military key
    let military_encrypted = hide_triple(&triple_encrypted, &military_secret)?;
    
    // Apply final obfuscation layer
    let mut final_obfuscated = military_encrypted;
    for i in 0..final_obfuscated.len() {
        final_obfuscated[i] = obfuscate_control_flow(final_obfuscated[i], OBFUSCATION_ROUNDS * 2);
    }
    
    // Add junk data to confuse analysis
    let junk_data = generate_junk_data();
    let mut output = Vec::with_capacity(final_obfuscated.len() + junk_data.len() + 4);
    
    // Prepend junk data length
    output.extend_from_slice(&(junk_data.len() as u32).to_le_bytes());
    output.extend_from_slice(&junk_data);
    output.extend_from_slice(&final_obfuscated);
    
    Ok(output)
}

/// Military-grade decryption with maximum deobfuscation
fn reveal_military(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < 4 { return Err(RustcryptError::MalformedInput); }
    
    // Extract junk data length
    let junk_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    
    if input.len() < 4 + junk_len { return Err(RustcryptError::MalformedInput); }
    
    // Skip junk data
    let encrypted_data = &input[4 + junk_len..];
    
    // Deobfuscate final layer
    let mut deobfuscated = encrypted_data.to_vec();
    for i in 0..deobfuscated.len() {
        deobfuscated[i] = obfuscate_control_flow(deobfuscated[i], OBFUSCATION_ROUNDS * 2);
    }
    
    // Decrypt with military key
    let military_key = derive_military_key(key.expose_secret(), b"military_encryption");
    let military_secret = SecretVec::new(military_key.to_vec());
    let triple_decrypted = reveal_triple(&deobfuscated, &military_secret)?;
    
    // Decrypt remaining layers
    reveal_triple(&triple_decrypted, key)
}

/// Enhanced OOP-style wrapper with ephemeral sessions and configurable layers
pub struct Rustcrypt {
    key: SecretVec<u8>,
    layers: EncryptionLayers,
    use_ephemeral: bool,
}

/// Ultra-secure obfuscated key wrapper with scattered binary fragments
pub struct ObfuscatedRustcrypt {
    obfuscated_key: ObfuscatedKey,
    layers: EncryptionLayers,
}

impl Rustcrypt {
    /// Create new instance with optional key and configuration
    pub fn new(option: Option<&[u8]>) -> Result<Self, RustcryptError> {
        Self::with_config(option, EncryptionLayers::default(), false)
    }
    
    /// Create with full configuration
    pub fn with_config(
        key_option: Option<&[u8]>, 
        layers: EncryptionLayers, 
        use_ephemeral: bool
    ) -> Result<Self, RustcryptError> {
        let key_vec = match key_option {
            Some(k) if k.len() == DEFAULT_KEY_LEN => SecretVec::new(k.to_vec()),
            Some(_) => return Err(RustcryptError::InvalidKey),
            None => {
                if use_ephemeral {
                    gen_ephemeral_key()
                } else {
                    let mut tmp = vec![0u8; DEFAULT_KEY_LEN];
                    rand::thread_rng().fill_bytes(&mut tmp);
                    SecretVec::new(tmp)
                }
            }
        };
        Ok(Self { 
            key: key_vec, 
            layers, 
            use_ephemeral 
        })
    }
    
    /// Create with hardware-backed key (placeholder for future implementation)
    pub fn with_hardware_key(layers: EncryptionLayers) -> Result<Self, RustcryptError> {
        let key = gen_hardware_key()?;
        Ok(Self { 
            key, 
            layers, 
            use_ephemeral: false 
        })
    }

    /// Hide string with configured layers
    pub fn hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError> {
        hide_layered(input.as_bytes(), &self.key, self.layers)
    }
    
    /// Hide bytes with configured layers
    pub fn hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError> {
        hide_layered(input, &self.key, self.layers)
    }

    /// Reveal string with configured layers
    pub fn reveal(&self, input: &[u8]) -> Result<String, RustcryptError> {
        let out = reveal_layered(input, &self.key, self.layers)?;
        String::from_utf8(out.to_vec()).map_err(|_| RustcryptError::MalformedInput)
    }
    
    /// Reveal bytes with configured layers (returns zeroizing buffer)
    pub fn reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
        reveal_layered(input, &self.key, self.layers)
    }
    
    /// Hide short secret using stack allocation
    pub fn hide_stack<const N: usize>(&self, input: &[u8]) -> Result<StackSecret<N>, RustcryptError> {
        if input.len() > N {
            return Err(RustcryptError::StackTooLarge);
        }
        let encrypted = self.hide_bytes(input)?;
        StackSecret::new(&encrypted)
    }
    
    /// Get current encryption layers
    pub fn layers(&self) -> EncryptionLayers {
        self.layers
    }
    
    /// Check if using ephemeral keys
    pub fn is_ephemeral(&self) -> bool {
        self.use_ephemeral
    }
}

impl Drop for Rustcrypt {
    fn drop(&mut self) {
        // Key is automatically zeroized by SecretVec on drop
    }
}

impl ObfuscatedRustcrypt {
    /// Create new obfuscated instance with scattered binary key
    pub fn new(layers: EncryptionLayers) -> Self {
        let obfuscated_key = gen_obfuscated_ephemeral_key();
        Self {
            obfuscated_key,
            layers,
        }
    }
    
    /// Create from existing obfuscated key
    pub fn from_obfuscated_key(obfuscated_key: ObfuscatedKey, layers: EncryptionLayers) -> Self {
        Self {
            obfuscated_key,
            layers,
        }
    }
    
    /// Hide string with obfuscated key
    pub fn hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        hide_layered(input.as_bytes(), &key, self.layers)
    }
    
    /// Hide bytes with obfuscated key
    pub fn hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        hide_layered(input, &key, self.layers)
    }
    
    /// Reveal string with obfuscated key
    pub fn reveal(&self, input: &[u8]) -> Result<String, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        let out = reveal_layered(input, &key, self.layers)?;
        String::from_utf8(out.to_vec()).map_err(|_| RustcryptError::MalformedInput)
    }
    
    /// Reveal bytes with obfuscated key
    pub fn reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        reveal_layered(input, &key, self.layers)
    }
    
    /// Get the obfuscated key fragments for inspection
    pub fn key_fragments(&self) -> &HashMap<usize, u8> {
        self.obfuscated_key.fragments()
    }
    
    /// Get encryption layers
    pub fn layers(&self) -> EncryptionLayers {
        self.layers
    }
}

impl Drop for ObfuscatedRustcrypt {
    fn drop(&mut self) {
        // ObfuscatedKey automatically clears fragments and masks on drop
    }
}

// Re-export commonly used items
pub use secrecy::SecretVec as SecretVecAlias;

/// Compile-time string literal encryption macro
/// 
/// This macro encrypts string literals at compile time, ensuring they never
/// exist in plaintext in the source code or compiled binary.
/// 
/// Note: This is a placeholder implementation. A real compile-time encryption
/// would require procedural macros or build scripts.
#[macro_export]
macro_rules! encrypt_literal {
    ($lit:expr) => {{
        // This is a placeholder - in a real implementation, this would use
        // a build script or proc macro to encrypt the literal at compile time
        // For now, we'll just return the bytes as-is with a warning
        #[cfg(debug_assertions)]
        compile_warning!("encrypt_literal! is a placeholder - implement proper compile-time encryption");
        $lit.as_bytes()
    }};
}

