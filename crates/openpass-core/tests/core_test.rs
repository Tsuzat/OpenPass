use openpass_core::*;

#[test]
fn rfc6238_sha1_vectors() {
    // RFC 6238 Appendix B, secret = ASCII "12345678901234567890", 8 digits
    let secret = b"12345678901234567890";
    assert_eq!(totp_at(secret, 59, 30, 8, TotpAlgorithm::Sha1), "94287082");
    assert_eq!(totp_at(secret, 1_111_111_109, 30, 8, TotpAlgorithm::Sha1), "07081804");
    assert_eq!(totp_at(secret, 1_234_567_890, 30, 8, TotpAlgorithm::Sha1), "89005924");
}

#[test]
fn key_hierarchy_roundtrip() {
    let params = KdfParams::test_fast(b"0123456789abcdef");
    let master = derive_master_key("correct horse battery staple", &params).unwrap();
    let verifier = auth_verifier(&master, &params).unwrap();
    let kek = key_encryption_key(&master, &params).unwrap();
    assert_ne!(verifier, kek, "auth and encryption keys must be domain-separated");

    let vault_key = random_key();
    let wrapped = wrap_key(&kek, &vault_key).unwrap();
    assert_eq!(unwrap_key(&kek, &wrapped).unwrap(), vault_key);

    // wrong password cannot unwrap
    let wrong = derive_master_key("wrong password", &params).unwrap();
    let wrong_kek = key_encryption_key(&wrong, &params).unwrap();
    assert!(unwrap_key(&wrong_kek, &wrapped).is_err());
}

#[test]
fn item_encryption_roundtrip_and_tamper() {
    let vault_key = random_key();
    let item = encrypt_item(&vault_key, "item-1", br#"{"v":1,"type":"login"}"#).unwrap();
    let pt = decrypt_item(&vault_key, "item-1", &item).unwrap();
    assert_eq!(pt, br#"{"v":1,"type":"login"}"#);
    // AAD binding: same ciphertext under a different item id must fail
    assert!(decrypt_item(&vault_key, "item-2", &item).is_err());
    // tamper detection: flip a character in the ciphertext
    let mut bad = item.clone();
    let mut w = bad.ciphertext_b64.into_bytes();
    let idx = w.len() / 2;
    w[idx] = if w[idx] == b'A' { b'B' } else { b'A' };
    bad.ciphertext_b64 = String::from_utf8(w).unwrap();
    assert!(decrypt_item(&vault_key, "item-1", &bad).is_err());
}

#[test]
fn recovery_proof_is_domain_separated() {
    let (_, key) = generate_recovery_key();
    let proof = recovery_auth_proof(&key);
    assert_ne!(proof, key, "proof must not reveal the recovery key/wrapper");
    assert_eq!(proof, recovery_auth_proof(&key), "proof is deterministic");
}

#[test]
fn recovery_key_roundtrip() {
    let (text, key) = generate_recovery_key();
    assert_eq!(parse_recovery_key(&text).unwrap(), key);
    assert_eq!(parse_recovery_key(&text.to_lowercase()).unwrap(), key);
}

#[test]
fn totp_base32_and_verify() {
    let secret = generate_totp_secret();
    let encoded = base32_encode(&secret);
    assert_eq!(base32_decode(&encoded).unwrap(), secret);
    let code = totp_at(&secret, 1_700_000_000, 30, 6, TotpAlgorithm::Sha1);
    assert_eq!(code.len(), 6);
    assert!(totp_verify(&secret, &code, 1_700_000_000, 30, 6, TotpAlgorithm::Sha1, 1));
}

#[test]
fn password_generator_length() {
    let p = generate_password(24);
    assert_eq!(p.chars().count(), 24);
}
