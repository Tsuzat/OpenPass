# Synced Passkeys — Implementation Plan (Phase 4)

## What exists now
- Rust core: ES256 P-256 keypair generation (PKCS#8), COSE public key encoding,
  sign/verify (`generate_passkey_keypair`, `passkey_sign`) — exposed via UniFFI + WASM, unit-tested.
- Vault item schema: `passkey { rpId, rpName, userName, credentialIdB64, privateKeyPkcs8B64, counter }` (inside item encryption).
- Platform service stubs: macOS `ASCredentialProviderExtension`, Android Credential Manager provider.

## Creation flow (per platform)
1. Relying party requests credential creation → OS routes to OpenPass provider.
2. Provider unlocks vault (biometric UV), calls core `generatePasskeyKeypair`.
3. Stores passkey item (private key only inside encrypted item), returns credential ID +
   COSE public key with attestation `none` (self-attestation), UV flag set, signCount 0.

## Assertion flow
1. RP challenge arrives with rpId + allow-list. Provider validates rpId against the item's rpId
   (exact match; Android also verifies asset-links/app signature origin mapping).
2. User selects credential + biometric UV → core signs `authenticatorData || SHA256(clientDataJSON)`.
3. Increments item counter, syncs updated item (counter field inside ciphertext).

## Rules
- Never sign when rpId mismatches the stored rpId; never export private keys outside the vault item.
- Backup eligibility/state flags: BS=1, BE=1 (synced). Counter is best-effort for synced passkeys.
- Discoverable credentials only for v1; per-RP credential listing filtered before any decryption.

## Platform notes
- macOS 14+: `ASPasskeyCredentialRegistrationRequest` / `ASPasskeyCredentialAssertionRequest` in the credential provider extension.
- Android 14+: Credential Manager provider `BeginCreatePublicKeyCredential` / assertion options parsing; JSON request formats per androidx.credentials.
- Web vault can create passkey items manually (RP ID + username) for sync/testing, but real
  ceremony registration happens through the OS providers, not the browser page.
