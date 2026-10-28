//! WASM surface for the web vault + browser extension.
//! JSON/base64 in-out; the master key itself is never returned to JS — only the
//! domain-separated AuthVerifier and KEK derived from it.

use base64ct::{Base64, Encoding};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{
    auth_verifier, decrypt_item, derive_master_key, encrypt_item, generate_password,
    generate_recovery_key, generate_totp_secret, key_encryption_key, parse_recovery_key, random_key,
    totp_at, unwrap_key, wrap_key, EncryptedItem, KdfParams, TotpAlgorithm,
};

fn b64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}
fn unb64(text: &str) -> Result<Vec<u8>, JsValue> {
    Base64::decode_vec(text).map_err(|_| JsValue::from_str("invalid base64"))
}
fn key32(text: &str) -> Result<[u8; 32], JsValue> {
    unb64(text)?.try_into().map_err(|_| JsValue::from_str("key must be 32 bytes"))
}
fn json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|_| JsValue::from_str("serialization failed"))
}
fn parse_params(params_json: &str) -> Result<KdfParams, JsValue> {
    serde_json::from_str(params_json).map_err(|_| JsValue::from_str("invalid kdf params"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthMaterial {
    auth_verifier_b64: String,
    kek_b64: String,
}

#[wasm_bindgen(js_name = generateKdfParams)]
pub fn generate_kdf_params() -> Result<String, JsValue> {
    json(&KdfParams::new_random().map_err(|_| JsValue::from_str("rng failed"))?)
}

/// Argon2id(password) -> { authVerifierB64, kekB64 }. Runs synchronously; call from a Web Worker.
#[wasm_bindgen(js_name = deriveAuthMaterial)]
pub fn derive_auth_material(password: &str, params_json: &str) -> Result<String, JsValue> {
    let params = parse_params(params_json)?;
    let master = derive_master_key(password, &params).map_err(|_| JsValue::from_str("kdf failed"))?;
    let out = AuthMaterial {
        auth_verifier_b64: b64(&auth_verifier(&master, &params).map_err(|_| JsValue::from_str("hkdf failed"))?),
        kek_b64: b64(&key_encryption_key(&master, &params).map_err(|_| JsValue::from_str("hkdf failed"))?),
    };
    json(&out)
}

#[wasm_bindgen(js_name = randomKeyB64)]
pub fn random_key_b64() -> String {
    b64(&random_key())
}

#[wasm_bindgen(js_name = wrapKeyB64)]
pub fn wrap_key_b64(wrapper_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let wrapped = wrap_key(&key32(wrapper_b64)?, &key32(key_b64)?).map_err(|_| JsValue::from_str("wrap failed"))?;
    Ok(b64(&wrapped))
}

#[wasm_bindgen(js_name = unwrapKeyB64)]
pub fn unwrap_key_b64(wrapper_b64: &str, blob_b64: &str) -> Result<String, JsValue> {
    let key = unwrap_key(&key32(wrapper_b64)?, &unb64(blob_b64)?).map_err(|_| JsValue::from_str("unwrap failed"))?;
    Ok(b64(&key))
}

#[wasm_bindgen(js_name = encryptItem)]
pub fn encrypt_item_js(vault_key_b64: &str, item_id: &str, plaintext_utf8: &str) -> Result<String, JsValue> {
    let item = encrypt_item(&key32(vault_key_b64)?, item_id, plaintext_utf8.as_bytes())
        .map_err(|_| JsValue::from_str("encrypt failed"))?;
    json(&item)
}

#[wasm_bindgen(js_name = decryptItem)]
pub fn decrypt_item_js(vault_key_b64: &str, item_id: &str, ciphertext_b64: &str, wrapped_item_key_b64: &str) -> Result<String, JsValue> {
    let item = EncryptedItem { ciphertext_b64: ciphertext_b64.to_string(), wrapped_item_key_b64: wrapped_item_key_b64.to_string() };
    let pt = decrypt_item(&key32(vault_key_b64)?, item_id, &item).map_err(|_| JsValue::from_str("decrypt failed"))?;
    String::from_utf8(pt).map_err(|_| JsValue::from_str("plaintext is not utf8"))
}

#[wasm_bindgen(js_name = generateRecoveryKey)]
pub fn generate_recovery_key_js() -> Result<String, JsValue> {
    let (text, key) = generate_recovery_key();
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out { text: String, key_b64: String }
    json(&Out { text, key_b64: b64(&key) })
}

#[wasm_bindgen(js_name = parseRecoveryKey)]
pub fn parse_recovery_key_js(text: &str) -> Result<String, JsValue> {
    Ok(b64(&parse_recovery_key(text).map_err(|_| JsValue::from_str("invalid recovery key"))?))
}

#[wasm_bindgen(js_name = recoveryAuthProof)]
pub fn recovery_auth_proof_js(recovery_key_b64: &str) -> Result<String, JsValue> {
    Ok(b64(&crate::recovery_auth_proof(&key32(recovery_key_b64)?)))
}

/// Arbitrary byte encryption (exports/backups). AAD binds the ciphertext to its purpose.
#[wasm_bindgen(js_name = encryptBytesB64)]
pub fn encrypt_bytes_js(key_b64: &str, plaintext_b64: &str, aad: &str) -> Result<String, JsValue> {
    let ct = crate::encrypt_bytes(&key32(key_b64)?, &unb64(plaintext_b64)?, aad.as_bytes())
        .map_err(|_| JsValue::from_str("encrypt failed"))?;
    Ok(b64(&ct))
}

#[wasm_bindgen(js_name = decryptBytesB64)]
pub fn decrypt_bytes_js(key_b64: &str, blob_b64: &str, aad: &str) -> Result<String, JsValue> {
    let pt = crate::decrypt_bytes(&key32(key_b64)?, &unb64(blob_b64)?, aad.as_bytes())
        .map_err(|_| JsValue::from_str("decrypt failed"))?;
    Ok(b64(&pt))
}

#[wasm_bindgen(js_name = encryptFileB64)]
pub fn encrypt_file_js(file_key_b64: &str, plaintext_b64: &str) -> Result<String, JsValue> {
    let ct = crate::encrypt_file(&key32(file_key_b64)?, &unb64(plaintext_b64)?)
        .map_err(|_| JsValue::from_str("file encrypt failed"))?;
    Ok(b64(&ct))
}

#[wasm_bindgen(js_name = decryptFileB64)]
pub fn decrypt_file_js(file_key_b64: &str, blob_b64: &str) -> Result<String, JsValue> {
    let pt = crate::decrypt_file(&key32(file_key_b64)?, &unb64(blob_b64)?)
        .map_err(|_| JsValue::from_str("file decrypt failed"))?;
    Ok(b64(&pt))
}

/// Derive a standalone key from a password (export backups). Returns { paramsJson, keyB64 }.
#[wasm_bindgen(js_name = deriveStandaloneKey)]
pub fn derive_standalone_key(password: &str) -> Result<String, JsValue> {
    let params = KdfParams::new_random().map_err(|_| JsValue::from_str("rng failed"))?;
    let key = derive_master_key(password, &params).map_err(|_| JsValue::from_str("kdf failed"))?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out { params: KdfParams, key_b64: String }
    json(&Out { params, key_b64: b64(&key) })
}

#[wasm_bindgen(js_name = deriveKeyWithParams)]
pub fn derive_key_with_params(password: &str, params_json: &str) -> Result<String, JsValue> {
    let params = parse_params(params_json)?;
    Ok(b64(&derive_master_key(password, &params).map_err(|_| JsValue::from_str("kdf failed"))?))
}

#[wasm_bindgen(js_name = generatePasskeyKeypair)]
pub fn generate_passkey_keypair_js() -> Result<String, JsValue> {
    let kp = crate::generate_passkey_keypair();
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out { private_key_pkcs8_b64: String, public_key_sec1_b64: String, cose_public_key_b64: String }
    json(&Out {
        private_key_pkcs8_b64: b64(&kp.private_key_pkcs8),
        public_key_sec1_b64: b64(&kp.public_key_sec1),
        cose_public_key_b64: b64(&crate::passkey_cose_public_key(&kp.public_key_sec1).map_err(|_| JsValue::from_str("cose failed"))?),
    })
}

#[wasm_bindgen(js_name = passkeySign)]
pub fn passkey_sign_js(private_key_pkcs8_b64: &str, data_b64: &str) -> Result<String, JsValue> {
    let sig = crate::passkey_sign(&unb64(private_key_pkcs8_b64)?, &unb64(data_b64)?)
        .map_err(|_| JsValue::from_str("sign failed"))?;
    Ok(b64(&sig))
}

#[wasm_bindgen(js_name = generateTotpSecretB32)]
pub fn generate_totp_secret_b32() -> String {
    crate::base32_encode(&generate_totp_secret())
}

#[wasm_bindgen(js_name = totpAt)]
pub fn totp_at_js(secret_b32: &str, unix_seconds: u64, period: u64, digits: u32, sha256: bool) -> Result<String, JsValue> {
    let secret = crate::base32_decode(secret_b32).map_err(|_| JsValue::from_str("invalid base32 secret"))?;
    Ok(totp_at(&secret, unix_seconds, period, digits, if sha256 { TotpAlgorithm::Sha256 } else { TotpAlgorithm::Sha1 }))
}

#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password_js(length: u32) -> String {
    generate_password(length as usize)
}
