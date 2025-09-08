use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use secrecy::{ExposeSecret, SecretVec};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_KEY_LEN: usize = 32;
pub const DEFAULT_NONCE_LEN: usize = 12;
pub const MAX_STACK_SECRET_LEN: usize = 256;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[derive(Clone, Copy)]
pub enum EncryptionLayers {
    Single,
    Double,
    Triple,
    Military,
}

impl Default for EncryptionLayers {
    fn default() -> Self {
        EncryptionLayers::Double
    }
}

fn to_key(key: &SecretVec<u8>) -> Result<aes_gcm::Key<aes_gcm::aes::Aes256>, RustcryptError> {
    if key.expose_secret().len() != DEFAULT_KEY_LEN {
        return Err(RustcryptError::InvalidKey);
    }
    Ok(aes_gcm::Key::<aes_gcm::aes::Aes256>::from_slice(key.expose_secret()).to_owned())
}

fn gen_nonce() -> [u8; DEFAULT_NONCE_LEN] {
    let mut nonce = [0u8; DEFAULT_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn obfuscate_control_flow(mut value: u8, rounds: usize) -> u8 {
    for r in 0..rounds {
        let mask = 0xA5u8.rotate_left((r % 8) as u32);
        value ^= mask;
    }
    value
}

fn derive_military_key(base_key: &[u8], context: &[u8]) -> [u8; 32] {
    let mut derived = [0u8; 32];
    let mut rng = rand::thread_rng();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    for round in 0..KEY_DERIVATION_ROUNDS {
        let mut round_key = [0u8; 32];
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
        for i in 0..32 {
            round_key[i] = obfuscate_control_flow(round_key[i], OBFUSCATION_ROUNDS);
        }
        for i in 0..32 {
            derived[i] ^= round_key[i];
        }
        let mut entropy = [0u8; 4];
        rng.fill_bytes(&mut entropy);
        let entropy_val = u32::from_le_bytes(entropy);
        for i in 0..32 {
            derived[i] = derived[i].wrapping_add(((entropy_val >> (i % 4)) & 0xFF) as u8);
        }
    }

    derived
}

fn generate_junk_data() -> Vec<u8> {
    let mut junk = vec![0u8; JUNK_DATA_SIZE];
    rand::thread_rng().fill_bytes(&mut junk);
    for i in (0..junk.len()).step_by(16) {
        if i + 15 < junk.len() {
            junk[i] = 0x2B;
            junk[i + 1] = 0x7E;
            junk[i + 2] = 0x15;
            junk[i + 3] = 0x16;
        }
    }

    junk
}

#[derive(Clone)]
pub struct ObfuscatedKey {
    fragments: HashMap<usize, u8>,
    masks: HashMap<usize, u8>,
    key_len: usize,
    #[allow(dead_code)]
    seed: u64,
    junk_data: Vec<u8>,
    obfuscation_level: usize,
}

impl ObfuscatedKey {
    pub fn new(key: &[u8]) -> Self {
        let mut rng = rand::thread_rng();
        let mut fragments = HashMap::new();
        let mut masks = HashMap::new();
        let junk_data = generate_junk_data();
        let derived_key = derive_military_key(key, b"military_grade_context");
        for (_, &byte) in derived_key.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> bit_idx) & 1;
                let fragment_pos = rng.gen_range(0..FRAGMENT_SPACE_SIZE);
                let mask = rng.gen::<u8>();
                let mut obfuscated_bit = bit;
                for _ in 0..OBFUSCATION_ROUNDS {
                    obfuscated_bit = obfuscate_control_flow(obfuscated_bit, 1);
                }
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
    pub fn reconstruct(&self) -> Result<Vec<u8>, RustcryptError> {
        let mut key = vec![0u8; self.key_len];
        let mut bit_positions = Vec::new();
        for &pos in self.fragments.keys() {
            bit_positions.push(pos);
        }
        bit_positions.sort();
        let mut current_byte = 0u8;
        let mut bit_count = 0;
        let mut byte_idx = 0;
        for &pos in &bit_positions {
            if let (Some(&fragment), Some(&mask)) = (self.fragments.get(&pos), self.masks.get(&pos))
            {
                let mut deobfuscated_bit = fragment ^ (mask & 1);
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
        for i in 0..key.len() {
            let junk_idx = i % self.junk_data.len();
            key[i] = key[i].wrapping_sub(self.junk_data[junk_idx]);
        }
        Ok(key)
    }
    pub fn fragments(&self) -> &HashMap<usize, u8> {
        &self.fragments
    }
}

impl Drop for ObfuscatedKey {
    fn drop(&mut self) {
        self.fragments.clear();
        self.masks.clear();
        self.junk_data.zeroize();
    }
}

fn gen_ephemeral_key() -> SecretVec<u8> {
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut key = [0u8; DEFAULT_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte ^= ((session_id >> (i % 8)) & 0xFF) as u8;
    }
    SecretVec::new(key.to_vec())
}

fn gen_obfuscated_ephemeral_key() -> ObfuscatedKey {
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut key = [0u8; DEFAULT_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte ^= ((session_id >> (i % 8)) & 0xFF) as u8;
    }
    ObfuscatedKey::new(&key)
}

fn gen_hardware_key() -> Result<SecretVec<u8>, RustcryptError> {
    Err(RustcryptError::HardwareKey)
}

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

pub fn hide_layered(
    input: &[u8],
    key: &SecretVec<u8>,
    layers: EncryptionLayers,
) -> Result<Vec<u8>, RustcryptError> {
    match layers {
        EncryptionLayers::Single => hide_single(input, key),
        EncryptionLayers::Double => hide_double(input, key),
        EncryptionLayers::Triple => hide_triple(input, key),
        EncryptionLayers::Military => hide_military(input, key),
    }
}

pub fn hide(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    hide_layered(input, key, EncryptionLayers::default())
}

fn hide_single(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    let key = to_key(key)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = gen_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut obfuscated_input = input.to_vec();
    for i in 0..obfuscated_input.len() {
        obfuscated_input[i] = obfuscate_control_flow(obfuscated_input[i], OBFUSCATION_ROUNDS);
    }
    let ct = cipher
        .encrypt(nonce, obfuscated_input.as_slice())
        .map_err(|_| RustcryptError::Encrypt)?;
    let mut obfuscated_ct = ct;
    for i in 0..obfuscated_ct.len() {
        obfuscated_ct[i] = obfuscate_control_flow(obfuscated_ct[i], OBFUSCATION_ROUNDS);
    }
    let mut out = Vec::with_capacity(DEFAULT_NONCE_LEN + obfuscated_ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&obfuscated_ct);
    Ok(out)
}

fn hide_double(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let stage1 = hide_single(input, key)?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), key.expose_secret());
    let mut xkey = [0u8; 32];
    hk.expand(b"double/xchacha", &mut xkey)
        .map_err(|_| RustcryptError::Encrypt)?;

    let xchacha = XChaCha20Poly1305::new_from_slice(&xkey).map_err(|_| RustcryptError::Encrypt)?;
    let mut xnonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut xnonce_bytes);
    let xnonce = XNonce::from_slice(&xnonce_bytes);
    let xct = xchacha
        .encrypt(xnonce, stage1.as_ref())
        .map_err(|_| RustcryptError::Encrypt)?;

    let mut out = Vec::with_capacity(16 + 24 + xct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&xnonce_bytes);
    out.extend_from_slice(&xct);
    Ok(out)
}

fn hide_triple(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    let stage2 = hide_double(input, key)?;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), key.expose_secret());
    let mut stream_mask = vec![0u8; stage2.len()];
    hk.expand(b"triple/mask", &mut stream_mask)
        .map_err(|_| RustcryptError::Encrypt)?;

    let mut obfuscated = stage2.clone();
    for (i, byte) in obfuscated.iter_mut().enumerate() {
        *byte ^= stream_mask[i];
    }

    let mut out = Vec::with_capacity(16 + obfuscated.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&obfuscated);
    Ok(out)
}

pub fn reveal_layered(
    input: &[u8],
    key: &SecretVec<u8>,
    layers: EncryptionLayers,
) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    match layers {
        EncryptionLayers::Single => reveal_single(input, key),
        EncryptionLayers::Double => reveal_double(input, key),
        EncryptionLayers::Triple => reveal_triple(input, key),
        EncryptionLayers::Military => reveal_military(input, key),
    }
}

pub fn reveal(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    reveal_layered(input, key, EncryptionLayers::default())
}

fn reveal_single(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < DEFAULT_NONCE_LEN {
        return Err(RustcryptError::MalformedInput);
    }
    let key = to_key(key)?;
    let cipher = Aes256Gcm::new(&key);
    let (nonce_part, ct) = input.split_at(DEFAULT_NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_part);

    let mut deobfuscated_ct = ct.to_vec();
    for i in 0..deobfuscated_ct.len() {
        deobfuscated_ct[i] = obfuscate_control_flow(deobfuscated_ct[i], OBFUSCATION_ROUNDS);
    }
    let mut pt = cipher
        .decrypt(nonce, deobfuscated_ct.as_slice())
        .map_err(|_| RustcryptError::Decrypt)?;
    for i in 0..pt.len() {
        pt[i] = obfuscate_control_flow(pt[i], OBFUSCATION_ROUNDS);
    }
    Ok(Zeroizing::new(pt))
}

fn reveal_double(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    if input.len() < 16 + 24 {
        return Err(RustcryptError::MalformedInput);
    }

    let (salt_part, rest) = input.split_at(16);
    let (xnonce_part, xct) = rest.split_at(24);
    let hk = Hkdf::<Sha256>::new(Some(salt_part), key.expose_secret());
    let mut xkey = [0u8; 32];
    hk.expand(b"double/xchacha", &mut xkey)
        .map_err(|_| RustcryptError::Decrypt)?;
    let xchacha = XChaCha20Poly1305::new_from_slice(&xkey).map_err(|_| RustcryptError::Decrypt)?;
    let xnonce = XNonce::from_slice(xnonce_part);
    let stage1 = xchacha
        .decrypt(xnonce, xct)
        .map_err(|_| RustcryptError::Decrypt)?;
    reveal_single(&stage1, key)
}

fn reveal_triple(input: &[u8], key: &SecretVec<u8>) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < 16 {
        return Err(RustcryptError::MalformedInput);
    }
    let (salt_part, obfuscated) = input.split_at(16);
    let hk = Hkdf::<Sha256>::new(Some(salt_part), key.expose_secret());
    let mut stream_mask = vec![0u8; obfuscated.len()];
    hk.expand(b"triple/mask", &mut stream_mask)
        .map_err(|_| RustcryptError::Decrypt)?;
    let mut deobfuscated = obfuscated.to_vec();
    for (i, byte) in deobfuscated.iter_mut().enumerate() {
        *byte ^= stream_mask[i];
    }
    reveal_double(&deobfuscated, key)
}

fn hide_military(input: &[u8], key: &SecretVec<u8>) -> Result<Vec<u8>, RustcryptError> {
    let triple_encrypted = hide_triple(input, key)?;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt), key.expose_secret());
    let mut military_key = [0u8; 32];
    hk.expand(b"military_encryption", &mut military_key)
        .map_err(|_| RustcryptError::Encrypt)?;
    let military_secret = SecretVec::new(military_key.to_vec());
    let military_encrypted = hide_triple(&triple_encrypted, &military_secret)?;
    let mut final_obfuscated = military_encrypted;
    for i in 0..final_obfuscated.len() {
        final_obfuscated[i] = obfuscate_control_flow(final_obfuscated[i], OBFUSCATION_ROUNDS * 2);
    }
    let junk_data = generate_junk_data();
    let mut output = Vec::with_capacity(final_obfuscated.len() + junk_data.len() + 4 + 16);
    output.extend_from_slice(&(junk_data.len() as u32).to_le_bytes());
    output.extend_from_slice(&junk_data);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&final_obfuscated);
    Ok(output)
}

fn reveal_military(
    input: &[u8],
    key: &SecretVec<u8>,
) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
    if input.len() < 4 {
        return Err(RustcryptError::MalformedInput);
    }
    let junk_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if input.len() < 4 + junk_len + 16 {
        return Err(RustcryptError::MalformedInput);
    }
    let after_junk = &input[4 + junk_len..];
    let (salt_part, encrypted_data) = after_junk.split_at(16);
    let mut deobfuscated = encrypted_data.to_vec();
    for i in 0..deobfuscated.len() {
        deobfuscated[i] = obfuscate_control_flow(deobfuscated[i], OBFUSCATION_ROUNDS * 2);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt_part), key.expose_secret());
    let mut military_key = [0u8; 32];
    hk.expand(b"military_encryption", &mut military_key)
        .map_err(|_| RustcryptError::Decrypt)?;
    let military_secret = SecretVec::new(military_key.to_vec());
    let triple_decrypted = reveal_triple(&deobfuscated, &military_secret)?;
    reveal_triple(&triple_decrypted, key)
}

pub struct Rustcrypt {
    key: SecretVec<u8>,
    layers: EncryptionLayers,
    use_ephemeral: bool,
}

pub struct ObfuscatedRustcrypt {
    obfuscated_key: ObfuscatedKey,
    layers: EncryptionLayers,
}

impl Rustcrypt {
    pub fn new(option: Option<&[u8]>) -> Result<Self, RustcryptError> {
        Self::with_config(option, EncryptionLayers::default(), false)
    }
    pub fn with_config(
        key_option: Option<&[u8]>,
        layers: EncryptionLayers,
        use_ephemeral: bool,
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
            use_ephemeral,
        })
    }

    pub fn with_hardware_key(layers: EncryptionLayers) -> Result<Self, RustcryptError> {
        let key = gen_hardware_key()?;
        Ok(Self {
            key,
            layers,
            use_ephemeral: false,
        })
    }

    pub fn hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError> {
        hide_layered(input.as_bytes(), &self.key, self.layers)
    }
    pub fn hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError> {
        hide_layered(input, &self.key, self.layers)
    }

    pub fn reveal(&self, input: &[u8]) -> Result<String, RustcryptError> {
        let out = reveal_layered(input, &self.key, self.layers)?;
        String::from_utf8(out.to_vec()).map_err(|_| RustcryptError::MalformedInput)
    }
    pub fn reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
        reveal_layered(input, &self.key, self.layers)
    }
    pub fn hide_stack<const N: usize>(
        &self,
        input: &[u8],
    ) -> Result<StackSecret<N>, RustcryptError> {
        if input.len() > N {
            return Err(RustcryptError::StackTooLarge);
        }
        let encrypted = self.hide_bytes(input)?;
        StackSecret::new(&encrypted)
    }
    pub fn layers(&self) -> EncryptionLayers {
        self.layers
    }
    pub fn is_ephemeral(&self) -> bool {
        self.use_ephemeral
    }
}

impl Drop for Rustcrypt {
    fn drop(&mut self) {}
}

impl ObfuscatedRustcrypt {
    pub fn new(layers: EncryptionLayers) -> Self {
        let obfuscated_key = gen_obfuscated_ephemeral_key();
        Self {
            obfuscated_key,
            layers,
        }
    }
    pub fn from_obfuscated_key(obfuscated_key: ObfuscatedKey, layers: EncryptionLayers) -> Self {
        Self {
            obfuscated_key,
            layers,
        }
    }
    pub fn hide(&self, input: &str) -> Result<Vec<u8>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        hide_layered(input.as_bytes(), &key, self.layers)
    }
    pub fn hide_bytes(&self, input: &[u8]) -> Result<Vec<u8>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        hide_layered(input, &key, self.layers)
    }
    pub fn reveal(&self, input: &[u8]) -> Result<String, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        let out = reveal_layered(input, &key, self.layers)?;
        String::from_utf8(out.to_vec()).map_err(|_| RustcryptError::MalformedInput)
    }
    pub fn reveal_bytes(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, RustcryptError> {
        let key_bytes = self.obfuscated_key.reconstruct()?;
        let key = SecretVec::new(key_bytes);
        reveal_layered(input, &key, self.layers)
    }
    pub fn key_fragments(&self) -> &HashMap<usize, u8> {
        self.obfuscated_key.fragments()
    }
    pub fn layers(&self) -> EncryptionLayers {
        self.layers
    }
}

impl Drop for ObfuscatedRustcrypt {
    fn drop(&mut self) {}
}

pub use secrecy::SecretVec as SecretVecAlias;

#[macro_export]
macro_rules! encrypt_literal {
    ($lit:expr) => {{
        $lit.as_bytes()
    }};
}
