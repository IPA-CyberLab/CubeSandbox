// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Secret protection for data stored in the AgentHub database.
//
//  - WebUI passwords are hashed one-way with bcrypt.
//  - Reversible secrets that must be used later (the DeepSeek API key and the
//    WeCom bot secret) are encrypted with AES-256-GCM and stored as
//    `enc:v1:<base64(nonce|ciphertext)>`.
//
// The symmetric key is taken from the `AGENTHUB_SECRET_KEY` environment
// variable. Set it to a strong, stable value in production (e.g. a 32-byte
// key, base64-encoded). When unset, a built-in development key is used so the
// feature works out of the box — this only obfuscates data at rest and MUST
// be overridden for any real deployment.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

const ENC_PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12;
/// 32-byte development fallback key. Override with AGENTHUB_SECRET_KEY.
const DEFAULT_DEV_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

/// Derives a 32-byte AES key from `AGENTHUB_SECRET_KEY` (base64 preferred,
/// otherwise raw bytes), padded/truncated to 32 bytes; falls back to the dev key.
fn load_key() -> [u8; 32] {
    let mut key = *DEFAULT_DEV_KEY;
    if let Ok(value) = std::env::var("AGENTHUB_SECRET_KEY") {
        let value = value.trim();
        if !value.is_empty() {
            let bytes = BASE64
                .decode(value)
                .unwrap_or_else(|_| value.as_bytes().to_vec());
            if bytes.len() >= 32 {
                key.copy_from_slice(&bytes[..32]);
            } else {
                key[..bytes.len()].copy_from_slice(&bytes);
            }
        }
    }
    key
}

/// Encrypts a UTF-8 secret, returning an `enc:v1:` tagged, base64 payload.
pub fn encrypt_secret(plaintext: &str) -> anyhow::Result<String> {
    let key = load_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    // 96-bit nonce from a fresh UUIDv4 (random) — unique per message.
    let uuid_bytes = *uuid::Uuid::new_v4().as_bytes();
    let nonce = Nonce::from_slice(&uuid_bytes[..NONCE_LEN]);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;
    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&uuid_bytes[..NONCE_LEN]);
    payload.extend_from_slice(&ciphertext);
    Ok(format!("{ENC_PREFIX}{}", BASE64.encode(payload)))
}

/// Decrypts an `enc:v1:` payload produced by [`encrypt_secret`].
pub fn decrypt_secret(stored: &str) -> anyhow::Result<String> {
    let encoded = stored
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("value is not encrypted"))?;
    let raw = BASE64.decode(encoded)?;
    if raw.len() <= NONCE_LEN {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let key = load_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e}"))?;
    Ok(String::from_utf8(plaintext)?)
}

/// Returns whether a stored value is in the encrypted envelope format.
pub fn is_encrypted(stored: &str) -> bool {
    stored.starts_with(ENC_PREFIX)
}

/// Decrypts an encrypted value, or returns the input unchanged when it is not
/// in the encrypted format (legacy plaintext rows) or cannot be decrypted.
pub fn decrypt_or_passthrough(stored: &str) -> String {
    if is_encrypted(stored) {
        decrypt_secret(stored).unwrap_or_else(|_| stored.to_string())
    } else {
        stored.to_string()
    }
}

/// Hashes a password with bcrypt.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| anyhow::anyhow!("hash failed: {e}"))
}

/// Verifies a candidate password against a stored value. bcrypt hashes start
/// with `$2`; anything else is treated as a legacy plaintext password.
pub fn verify_password(stored: &str, candidate: &str) -> bool {
    if stored.starts_with("$2") {
        bcrypt::verify(candidate, stored).unwrap_or(false)
    } else {
        stored == candidate
    }
}
