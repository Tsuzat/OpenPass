//! UniFFI surface for Swift/Kotlin. Thin conversions over the core API — no crypto logic here.

use crate::{
    auth_verifier, decrypt_item, derive_master_key, encrypt_item, generate_password,
    generate_recovery_key, generate_totp_secret, key_encryption_key, parse_recovery_key, random_key,
    totp_at, unwrap_key, wrap_key, EncryptedItem, KdfParams, TotpAlgorithm,
};

#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    Kdf,
    Encoding,
    Crypto,
    InvalidKeyLength,
}

impl From<crate::Error> for FfiError {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Kdf => FfiError::Kdf,
            crate::Error::Encoding => FfiError::Encoding,
            crate::Error::Crypto => FfiError::Crypto,
            crate::Error::InvalidKeyLength => FfiError::InvalidKeyLength,
        }
    }
}
impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for FfiError {}

#[derive(uniffi::Record)]
pub struct RecoveryKey {
    pub text: String,
    pub key: Vec<u8>,
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], FfiError> {
    bytes.try_into().map_err(|_| FfiError::InvalidKeyLength)
}

#[uniffi::export]
pub fn ffi_derive_master_key(password: String, params: KdfParams) -> Result<Vec<u8>, FfiError> {
    Ok(derive_master_key(&password, &params).map_err(FfiError::from)?.to_vec())
}

#[uniffi::export]
pub fn ffi_auth_verifier(master_key: Vec<u8>, params: KdfParams) -> Result<Vec<u8>, FfiError> {
    Ok(auth_verifier(&key32(&master_key)?, &params).map_err(FfiError::from)?.to_vec())
}

#[uniffi::export]
pub fn ffi_key_encryption_key(master_key: Vec<u8>, params: KdfParams) -> Result<Vec<u8>, FfiError> {
    Ok(key_encryption_key(&key32(&master_key)?, &params).map_err(FfiError::from)?.to_vec())
}

#[uniffi::export]
pub fn ffi_random_key() -> Vec<u8> {
    random_key().to_vec()
}

#[uniffi::export]
pub fn ffi_new_kdf_params() -> Result<KdfParams, FfiError> {
    KdfParams::new_random().map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_wrap_key(wrapper: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    wrap_key(&key32(&wrapper)?, &key32(&key)?).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_unwrap_key(wrapper: Vec<u8>, blob: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    Ok(unwrap_key(&key32(&wrapper)?, &blob).map_err(FfiError::from)?.to_vec())
}

#[uniffi::export]
pub fn ffi_encrypt_item(vault_key: Vec<u8>, item_id: String, plaintext: Vec<u8>) -> Result<EncryptedItem, FfiError> {
    encrypt_item(&key32(&vault_key)?, &item_id, &plaintext).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_decrypt_item(vault_key: Vec<u8>, item_id: String, item: EncryptedItem) -> Result<Vec<u8>, FfiError> {
    decrypt_item(&key32(&vault_key)?, &item_id, &item).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_generate_recovery_key() -> RecoveryKey {
    let (text, key) = generate_recovery_key();
    RecoveryKey { text, key: key.to_vec() }
}

#[uniffi::export]
pub fn ffi_parse_recovery_key(text: String) -> Result<Vec<u8>, FfiError> {
    Ok(parse_recovery_key(&text).map_err(FfiError::from)?.to_vec())
}

#[uniffi::export]
pub fn ffi_recovery_auth_proof(recovery_key: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    Ok(crate::recovery_auth_proof(&key32(&recovery_key)?).to_vec())
}

#[uniffi::export]
pub fn ffi_encrypt_bytes(key: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::encrypt_bytes(&key32(&key)?, &plaintext, &aad).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_decrypt_bytes(key: Vec<u8>, blob: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::decrypt_bytes(&key32(&key)?, &blob, &aad).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_encrypt_file(file_key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::encrypt_file(&key32(&file_key)?, &plaintext).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_decrypt_file(file_key: Vec<u8>, blob: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::decrypt_file(&key32(&file_key)?, &blob).map_err(FfiError::from)
}

#[derive(uniffi::Record)]
pub struct PasskeyKeyPairFfi {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
}

#[uniffi::export]
pub fn ffi_generate_passkey_keypair() -> PasskeyKeyPairFfi {
    let kp = crate::generate_passkey_keypair();
    PasskeyKeyPairFfi { private_key_pkcs8: kp.private_key_pkcs8, public_key_sec1: kp.public_key_sec1 }
}

#[uniffi::export]
pub fn ffi_passkey_cose_public_key(public_key_sec1: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::passkey_cose_public_key(&public_key_sec1).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_passkey_sign(private_key_pkcs8: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    crate::passkey_sign(&private_key_pkcs8, &data).map_err(FfiError::from)
}

#[uniffi::export]
pub fn ffi_generate_totp_secret() -> Vec<u8> {
    generate_totp_secret()
}

#[uniffi::export]
pub fn ffi_totp_at(secret: Vec<u8>, unix_seconds: u64, period: u64, digits: u32, algorithm: TotpAlgorithm) -> String {
    totp_at(&secret, unix_seconds, period, digits, algorithm)
}

#[uniffi::export]
pub fn ffi_generate_password(length: u32) -> String {
    generate_password(length as usize)
}
