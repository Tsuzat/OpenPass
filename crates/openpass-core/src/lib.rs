//! OpenPass crypto core — spec: docs/CRYPTO.md
//! Native clients use the UniFFI surface (`ffi` module, feature `uniffi`);
//! web/extension use the WASM surface (`wasm` module, feature `wasm`).

#[cfg(feature = "uniffi")]
mod ffi;
#[cfg(feature = "uniffi")]
pub use ffi::{FfiError, RecoveryKey};

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

pub const BLOB_VERSION: u8 = 0x01;
const AUTH_INFO: &[u8] = b"openpass/auth/v1";
const KEK_INFO: &[u8] = b"openpass/kek/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt_b64: String,
}

impl KdfParams {
    pub fn new_random() -> Result<Self, Error> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Ok(Self { memory_kib: 65_536, iterations: 3, parallelism: 4, salt_b64: Base64::encode_string(&salt) })
    }
    /// Fast params for tests only.
    pub fn test_fast(salt: &[u8]) -> Self {
        Self { memory_kib: 8_192, iterations: 1, parallelism: 1, salt_b64: Base64::encode_string(salt) }
    }
    fn salt(&self) -> Result<Vec<u8>, Error> {
        Base64::decode_vec(&self.salt_b64).map_err(|_| Error::Encoding)
    }
}

#[derive(Debug)]
pub enum Error {
    Kdf,
    Encoding,
    Crypto,
    InvalidKeyLength,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

fn hkdf(master: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32-byte HKDF output is valid");
    out
}

/// Argon2id(password) -> MasterKey
pub fn derive_master_key(password: &str, params: &KdfParams) -> Result<[u8; 32], Error> {
    let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), &params.salt()?, &mut out).map_err(|_| Error::Kdf)?;
    Ok(out)
}

pub fn auth_verifier(master: &[u8; 32], params: &KdfParams) -> Result<[u8; 32], Error> {
    Ok(hkdf(master, &params.salt()?, AUTH_INFO))
}
pub fn key_encryption_key(master: &[u8; 32], params: &KdfParams) -> Result<[u8; 32], Error> {
    Ok(hkdf(master, &params.salt()?, KEK_INFO))
}

pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

fn aead(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Wrap `key` with `wrapper`: output = version(1) || nonce(24) || ct
pub fn wrap_key(wrapper: &[u8; 32], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = aead(wrapper)
        .encrypt(XNonce::from_slice(&nonce), key.as_slice())
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(1 + 24 + ct.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unwrap_key(wrapper: &[u8; 32], blob: &[u8]) -> Result<[u8; 32], Error> {
    if blob.len() < 1 + 24 + 16 || blob[0] != BLOB_VERSION {
        return Err(Error::Crypto);
    }
    let pt = aead(wrapper)
        .decrypt(XNonce::from_slice(&blob[1..25]), &blob[25..])
        .map_err(|_| Error::Crypto)?;
    let key: [u8; 32] = pt.try_into().map_err(|_| Error::InvalidKeyLength)?;
    Ok(key)
}

/// Encrypt arbitrary bytes: version || nonce || ct, with AAD bound to context (e.g. item id).
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = aead(key)
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(1 + 24 + ct.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_bytes(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < 1 + 24 + 16 || blob[0] != BLOB_VERSION {
        return Err(Error::Crypto);
    }
    aead(key)
        .decrypt(XNonce::from_slice(&blob[1..25]), Payload { msg: &blob[25..], aad })
        .map_err(|_| Error::Crypto)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct EncryptedItem {
    /// base64: item encrypted under a random per-item key
    pub ciphertext_b64: String,
    /// base64: per-item key wrapped by the vault key
    pub wrapped_item_key_b64: String,
}

pub fn encrypt_item(vault_key: &[u8; 32], item_id: &str, plaintext_json: &[u8]) -> Result<EncryptedItem, Error> {
    let item_key = random_key();
    let ct = encrypt_bytes(&item_key, plaintext_json, item_id.as_bytes())?;
    let wrapped = wrap_key(vault_key, &item_key)?;
    let mut ik = item_key;
    ik.zeroize();
    Ok(EncryptedItem {
        ciphertext_b64: Base64::encode_string(&ct),
        wrapped_item_key_b64: Base64::encode_string(&wrapped),
    })
}

pub fn decrypt_item(vault_key: &[u8; 32], item_id: &str, item: &EncryptedItem) -> Result<Vec<u8>, Error> {
    let wrapped = Base64::decode_vec(&item.wrapped_item_key_b64).map_err(|_| Error::Encoding)?;
    let ct = Base64::decode_vec(&item.ciphertext_b64).map_err(|_| Error::Encoding)?;
    let item_key = unwrap_key(vault_key, &wrapped)?;
    decrypt_bytes(&item_key, &ct, item_id.as_bytes())
}

/// 256-bit recovery key encoded as grouped Base32: XXXX-XXXX-... (13 groups of 4 + padding group)
pub fn generate_recovery_key() -> (String, [u8; 32]) {
    let key = random_key();
    let encoded = data_encoding::BASE32_NOPAD.encode(&key);
    let grouped = encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    (grouped, key)
}

pub fn parse_recovery_key(text: &str) -> Result<[u8; 32], Error> {
    let cleaned: String = text.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let bytes = data_encoding::BASE32_NOPAD.decode(cleaned.to_uppercase().as_bytes()).map_err(|_| Error::Encoding)?;
    bytes.try_into().map_err(|_| Error::InvalidKeyLength)
}

// ---------- TOTP (RFC 6238) ----------

pub fn generate_totp_secret() -> Vec<u8> {
    let mut s = vec![0u8; 20];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn base32_encode(data: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(data)
}
pub fn base32_decode(text: &str) -> Result<Vec<u8>, Error> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    data_encoding::BASE32_NOPAD.decode(cleaned.to_uppercase().as_bytes()).map_err(|_| Error::Encoding)
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
}

fn hotp(secret: &[u8], counter: u64, digits: u32, alg: TotpAlgorithm) -> String {
    let msg = counter.to_be_bytes();
    let hash: Vec<u8> = match alg {
        TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let code = ((u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]))
        % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

pub fn totp_at(secret: &[u8], unix_seconds: u64, period: u64, digits: u32, alg: TotpAlgorithm) -> String {
    hotp(secret, unix_seconds / period, digits, alg)
}

pub fn totp_verify(secret: &[u8], code: &str, unix_seconds: u64, period: u64, digits: u32, alg: TotpAlgorithm, window: i64) -> bool {
    let counter = (unix_seconds / period) as i64;
    (-window..=window).any(|w| {
        let c = (counter + w).max(0) as u64;
        hotp(secret, c, digits, alg) == code
    })
}

// ---------- Password generator ----------

const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

pub fn generate_password(length: usize) -> String {
    let mut out = String::with_capacity(length);
    let mut byte = [0u8; 1];
    while out.len() < length {
        OsRng.fill_bytes(&mut byte);
        // rejection sampling to avoid modulo bias
        let limit = 256 - (256 % CHARSET.len());
        if (byte[0] as usize) < limit {
            out.push(CHARSET[(byte[0] as usize) % CHARSET.len()] as char);
        }
    }
    out
}
