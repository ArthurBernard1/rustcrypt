use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use chacha20poly1305::{aead::Aead as Aead2, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use super::keystore;

fn unmask_keys() -> ([u8; 32], [u8; 32]) {
    let mut k1 = keystore::K1_MASKED;
    let mut k2 = keystore::K2_MASKED;
    for i in 0..32 {
        k1[i] ^= keystore::MASK_KEY[i];
        k2[i] ^= keystore::MASK_KEY[i];
    }
    (k1, k2)
}

fn remove_stuffing(stuffed: &[u8], step: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(stuffed.len());
    for (i, b) in stuffed.iter().enumerate() {
        if match step { 1 => i % 3 != 1, 2 => i % 2 != 1, _ => true } {
            out.push(*b);
        }
    }
    out
}

pub fn decrypt_secret() -> Result<Zeroizing<Vec<u8>>> {
    let (k1, k2) = unmask_keys();

    // Stage 2 first: XChaCha20Poly1305 decrypt
    let xchacha = XChaCha20Poly1305::new_from_slice(&k2).map_err(|e| anyhow!("xchacha key: {e}"))?;
    let xnonce = XNonce::from_slice(&keystore::XNONCE);
    let xct = remove_stuffing(keystore::XCT, 2);
    let stage1_concat = xchacha.decrypt(xnonce, xct.as_ref()).map_err(|_| anyhow!("stage2 decrypt failed"))?;

    // Split stage1_concat back into shards by LENGTHS
    let mut shards: Vec<&[u8]> = Vec::new();
    let mut cursor = 0usize;
    for len in keystore::LENGTHS {
        let end = cursor + len;
        if end > stage1_concat.len() { return Err(anyhow!("stage1 lengths mismatch")); }
        shards.push(&stage1_concat[cursor..end]);
        cursor = end;
    }

    let gcm = Aes256Gcm::new_from_slice(&k1).map_err(|e| anyhow!("gcm key: {e}"))?;

    let mut plaintext_parts: Vec<u8> = Vec::new();
    for (i, shard_ct) in shards.iter().enumerate() {
        let nonce = Nonce::from_slice(&keystore::STAGE1_NONCES[i]);
        let pt = gcm.decrypt(nonce, shard_ct.as_ref()).map_err(|_| anyhow!("stage1 decrypt failed"))?;
        plaintext_parts.extend_from_slice(&pt);
    }

    Ok(Zeroizing::new(plaintext_parts))
}

