CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
  verifier_hash TEXT NOT NULL, kdf_salt_b64 TEXT NOT NULL, kdf_params_json TEXT NOT NULL,
  wrapped_vault_key_b64 TEXT NOT NULL, recovery_wrapped_vault_key_b64 TEXT NOT NULL,
  identity_public_key_b64 TEXT NOT NULL, wrapped_identity_private_key_b64 TEXT NOT NULL,
  vault_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, name TEXT NOT NULL, platform TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
  access_hash TEXT NOT NULL, refresh_hash TEXT NOT NULL, prev_refresh_hash TEXT,
  access_expires_at INTEGER NOT NULL, refresh_expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_access ON sessions(access_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh ON sessions(refresh_hash);
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, user_id TEXT NOT NULL, type TEXT NOT NULL,
  ciphertext_b64 TEXT NOT NULL, wrapped_item_key_b64 TEXT NOT NULL,
  revision INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_vault_updated ON items(vault_id, updated_at);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, user_id TEXT, event TEXT NOT NULL, meta TEXT NOT NULL, created_at TEXT NOT NULL
);
