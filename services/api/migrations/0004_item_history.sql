CREATE TABLE IF NOT EXISTS item_history (
  id TEXT PRIMARY KEY, item_id TEXT NOT NULL, vault_id TEXT NOT NULL,
  revision INTEGER NOT NULL, ciphertext_b64 TEXT NOT NULL, wrapped_item_key_b64 TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, archived_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_item ON item_history(vault_id, item_id, revision DESC);
