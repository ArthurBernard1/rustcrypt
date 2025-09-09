use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const SALT_LENGTH: u8 = 8;
const DEFAULT_SEPARATOR: &str = "$";
const VERSION: &str = "o1";

#[derive(Debug)]
pub enum TextObfError { Invalid, Unsupported, Encrypt, Decrypt, B64, Rng }

impl From<aes_gcm::Error> for TextObfError { fn from(_: aes_gcm::Error) -> Self { TextObfError::Decrypt } }

#[derive(Clone)]
pub struct TextObfConfig { passphrase: Vec<u8>, salt_length: u8, separator: String, iterations: u32 }

pub struct TextObfuscator { config: TextObfConfig }

impl TextObfuscator {
    pub fn new(passphrase: &[u8]) -> Self {
        if passphrase.is_empty() { panic!("empty passphrase") }
        let config = TextObfConfig { passphrase: passphrase.to_vec(), salt_length: SALT_LENGTH, separator: DEFAULT_SEPARATOR.to_string(), iterations: 1000 };
        Self { config }
    }
    pub fn with_salt_length(mut self, length: u8) -> Self { if length == 0 { panic!("salt length 0") } self.config.salt_length = length; self }
    pub fn with_separator(mut self, separator: &str) -> Self { self.config.separator = separator.to_string(); self }
    pub fn with_iterations(mut self, iterations: u32) -> Self { if iterations == 0 { panic!("iterations 0") } self.config.iterations = iterations; self }
    pub fn obfuscate(&self, text: &str) -> Result<String, TextObfError> {
        let salt = self.gen_salt(self.config.salt_length)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let iv = self.gen_iv()?;
        let ct = self.encrypt(text.as_bytes(), &key, &iv)?;
        let es = STANDARD.encode(&salt);
        let ei = STANDARD.encode(&iv);
        let ec = STANDARD.encode(&ct);
        Ok(format!("{}{}{}{}{}{}{}{}", self.config.separator, VERSION, self.config.separator, es, self.config.separator, ei, self.config.separator, ec))
    }
    pub fn unobfuscate(&self, s: &str) -> Result<String, TextObfError> {
        let parts: Vec<&str> = s.split(&self.config.separator).collect();
        let parts = if parts.first().map(|x| x.is_empty()).unwrap_or(false) { &parts[1..] } else { &parts[..] };
        if parts.len() != 4 { return Err(TextObfError::Invalid) }
        match parts[0] { "o1" => { let b = self.decrypt(parts)?; Ok(String::from_utf8_lossy(&b).to_string()) }, _ => Err(TextObfError::Unsupported) }
    }
    pub fn obfuscate_bytes(&self, bytes: &[u8]) -> Result<String, TextObfError> {
        let salt = self.gen_salt(self.config.salt_length)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let iv = self.gen_iv()?;
        let ct = self.encrypt(bytes, &key, &iv)?;
        let es = STANDARD.encode(&salt);
        let ei = STANDARD.encode(&iv);
        let ec = STANDARD.encode(&ct);
        Ok(format!("{}{}{}{}{}{}{}{}", self.config.separator, VERSION, self.config.separator, es, self.config.separator, ei, self.config.separator, ec))
    }
    pub fn unobfuscate_bytes(&self, s: &str) -> Result<Zeroizing<Vec<u8>>, TextObfError> {
        let parts: Vec<&str> = s.split(&self.config.separator).collect();
        let parts = if parts.first().map(|x| x.is_empty()).unwrap_or(false) { &parts[1..] } else { &parts[..] };
        if parts.len() != 4 { return Err(TextObfError::Invalid) }
        match parts[0] { "o1" => { let b = self.decrypt(parts)?; Ok(Zeroizing::new(b)) }, _ => Err(TextObfError::Unsupported) }
    }
    pub fn obfuscate_to_parts(&self, input: &[u8]) -> Result<(String, String, String), TextObfError> {
        let salt = self.gen_salt(self.config.salt_length)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let iv = self.gen_iv()?;
        let ct = self.encrypt(input, &key, &iv)?;
        Ok((STANDARD.encode(&salt), STANDARD.encode(&iv), STANDARD.encode(&ct)))
    }
    pub fn unobfuscate_from_parts(&self, salt_b64: &str, iv_b64: &str, ct_b64: &str) -> Result<Zeroizing<Vec<u8>>, TextObfError> {
        let salt = STANDARD.decode(salt_b64).map_err(|_| TextObfError::B64)?;
        let iv = STANDARD.decode(iv_b64).map_err(|_| TextObfError::B64)?;
        let ct = STANDARD.decode(ct_b64).map_err(|_| TextObfError::B64)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| TextObfError::Encrypt)?;
        let nonce = Nonce::from_slice(&iv);
        let out = cipher.decrypt(nonce, ct.as_ref()).map_err(TextObfError::from)?;
        Ok(Zeroizing::new(out))
    }
    fn decrypt(&self, p: &[&str]) -> Result<Vec<u8>, TextObfError> {
        let salt = STANDARD.decode(p[1]).map_err(|_| TextObfError::B64)?;
        let iv = STANDARD.decode(p[2]).map_err(|_| TextObfError::B64)?;
        let ct = STANDARD.decode(p[3]).map_err(|_| TextObfError::B64)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| TextObfError::Encrypt)?;
        let nonce = Nonce::from_slice(&iv);
        let out = cipher.decrypt(nonce, ct.as_ref()).map_err(TextObfError::from)?;
        Ok(out)
    }
    fn encrypt(&self, bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, TextObfError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| TextObfError::Encrypt)?;
        let nonce = Nonce::from_slice(iv);
        let out = cipher.encrypt(nonce, bytes).map_err(|_| TextObfError::Encrypt)?;
        Ok(out)
    }
    fn gen_salt(&self, len: u8) -> Result<Vec<u8>, TextObfError> { let mut s = vec![0u8; len as usize]; OsRng.try_fill_bytes(&mut s).map_err(|_| TextObfError::Rng)?; Ok(s) }
    fn derive_key(&self, pass: &[u8], salt: &[u8]) -> Vec<u8> { let mut k = [0u8; 32]; pbkdf2_hmac::<Sha256>(pass, salt, self.config.iterations, &mut k); k.to_vec() }
    fn gen_iv(&self) -> Result<Vec<u8>, TextObfError> { let mut iv = vec![0u8; 12]; OsRng.try_fill_bytes(&mut iv).map_err(|_| TextObfError::Rng)?; Ok(iv) }
}

pub const TEXT_OBF_DEFAULT_SEPARATOR: &str = DEFAULT_SEPARATOR;

impl Drop for TextObfuscator { fn drop(&mut self) { self.config.passphrase.zeroize(); } }

