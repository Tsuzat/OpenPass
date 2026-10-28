import type { AttachmentRow, DeviceRow, ItemRow, SessionRow, Store, UserRow } from "./types";

// Minimal D1Database structural type (avoids hard dependency in shared code paths)
interface D1Prepared { bind(...v: unknown[]): D1Prepared; first<T>(): Promise<T | null>; all<T>(): Promise<{ results: T[] }>; run(): Promise<unknown>; }
interface D1Like { prepare(sql: string): D1Prepared; }

const U = "id,email,verifier_hash,kdf_salt_b64,kdf_params_json,wrapped_vault_key_b64,recovery_wrapped_vault_key_b64,identity_public_key_b64,wrapped_identity_private_key_b64,recovery_verifier_hash,vault_id,created_at";
function mapUser(r: Record<string, unknown>): UserRow {
  return { id: r.id as string, email: r.email as string, verifierHash: r.verifier_hash as string, kdfSaltB64: r.kdf_salt_b64 as string, kdfParamsJson: r.kdf_params_json as string, wrappedVaultKeyB64: r.wrapped_vault_key_b64 as string, recoveryWrappedVaultKeyB64: r.recovery_wrapped_vault_key_b64 as string, identityPublicKeyB64: r.identity_public_key_b64 as string, wrappedIdentityPrivateKeyB64: r.wrapped_identity_private_key_b64 as string, recoveryVerifierHash: (r.recovery_verifier_hash as string) ?? "", vaultId: r.vault_id as string, createdAt: r.created_at as string };
}
function mapDevice(r: Record<string, unknown>): DeviceRow {
  return { userId: r.user_id as string, deviceId: r.device_id as string, name: r.name as string, platform: r.platform as string, status: r.status as "approved" | "pending", createdAt: r.created_at as string, lastSeenAt: r.last_seen_at as string };
}
function mapSession(r: Record<string, unknown>): SessionRow {
  return { id: r.id as string, userId: r.user_id as string, deviceId: r.device_id as string, accessHash: r.access_hash as string, refreshHash: r.refresh_hash as string, prevRefreshHash: (r.prev_refresh_hash as string) ?? null, accessExpiresAt: r.access_expires_at as number, refreshExpiresAt: r.refresh_expires_at as number, revoked: r.revoked as number, createdAt: r.created_at as string };
}
function mapItem(r: Record<string, unknown>): ItemRow {
  return { id: r.id as string, vaultId: r.vault_id as string, userId: r.user_id as string, type: r.type as string, ciphertextB64: r.ciphertext_b64 as string, wrappedItemKeyB64: r.wrapped_item_key_b64 as string, revision: r.revision as number, deleted: r.deleted as number, updatedAt: r.updated_at as string };
}

export class D1Store implements Store {
  constructor(private db: D1Like) {}
  async getUserByEmail(email: string) { const r = await this.db.prepare(`SELECT ${U} FROM users WHERE email=?`).bind(email).first<Record<string, unknown>>(); return r ? mapUser(r) : null; }
  async getUserById(id: string) { const r = await this.db.prepare(`SELECT ${U} FROM users WHERE id=?`).bind(id).first<Record<string, unknown>>(); return r ? mapUser(r) : null; }
  async createUser(u: UserRow) { await this.db.prepare(`INSERT INTO users (${U}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).bind(u.id, u.email, u.verifierHash, u.kdfSaltB64, u.kdfParamsJson, u.wrappedVaultKeyB64, u.recoveryWrappedVaultKeyB64, u.identityPublicKeyB64, u.wrappedIdentityPrivateKeyB64, u.recoveryVerifierHash, u.vaultId, u.createdAt).run(); }
  async updateUserVerifier(userId: string, verifierHash: string, w: string, rw: string, salt: string, params: string) { await this.db.prepare(`UPDATE users SET verifier_hash=?,wrapped_vault_key_b64=?,recovery_wrapped_vault_key_b64=?,kdf_salt_b64=?,kdf_params_json=? WHERE id=?`).bind(verifierHash, w, rw, salt, params, userId).run(); }
  async getDevice(userId: string, deviceId: string) { const r = await this.db.prepare(`SELECT * FROM devices WHERE user_id=? AND device_id=?`).bind(userId, deviceId).first<Record<string, unknown>>(); return r ? mapDevice(r) : null; }
  async upsertDevice(d: DeviceRow) { await this.db.prepare(`INSERT INTO devices (user_id,device_id,name,platform,status,created_at,last_seen_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET name=excluded.name,platform=excluded.platform,last_seen_at=excluded.last_seen_at`).bind(d.userId, d.deviceId, d.name, d.platform, d.status, d.createdAt, d.lastSeenAt).run(); }
  async listDevices(userId: string) { const { results } = await this.db.prepare(`SELECT * FROM devices WHERE user_id=?`).bind(userId).all<Record<string, unknown>>(); return results.map(mapDevice); }
  async listPendingDevices(userId: string) { const { results } = await this.db.prepare(`SELECT * FROM devices WHERE user_id=? AND status='pending'`).bind(userId).all<Record<string, unknown>>(); return results.map(mapDevice); }
  async setDeviceStatus(userId: string, deviceId: string, status: string) { await this.db.prepare(`UPDATE devices SET status=? WHERE user_id=? AND device_id=?`).bind(status, userId, deviceId).run(); }
  async deleteDevice(userId: string, deviceId: string) { await this.db.prepare(`DELETE FROM devices WHERE user_id=? AND device_id=?`).bind(userId, deviceId).run(); }
  async getDeviceStatus(deviceId: string) { const r = await this.db.prepare(`SELECT status FROM devices WHERE device_id=?`).bind(deviceId).first<{ status: string }>(); return r ? (r.status as "approved" | "pending") : "unknown"; }
  async createSession(s: SessionRow) { await this.db.prepare(`INSERT INTO sessions (id,user_id,device_id,access_hash,refresh_hash,prev_refresh_hash,access_expires_at,refresh_expires_at,revoked,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`).bind(s.id, s.userId, s.deviceId, s.accessHash, s.refreshHash, s.prevRefreshHash, s.accessExpiresAt, s.refreshExpiresAt, s.revoked, s.createdAt).run(); }
  async getSessionByAccessHash(hash: string) { const r = await this.db.prepare(`SELECT * FROM sessions WHERE access_hash=?`).bind(hash).first<Record<string, unknown>>(); return r ? mapSession(r) : null; }
  async getSessionByRefreshHash(hash: string) { const r = await this.db.prepare(`SELECT * FROM sessions WHERE refresh_hash=?`).bind(hash).first<Record<string, unknown>>(); return r ? mapSession(r) : null; }
  async getSessionByPrevRefreshHash(hash: string) { const r = await this.db.prepare(`SELECT * FROM sessions WHERE prev_refresh_hash=?`).bind(hash).first<Record<string, unknown>>(); return r ? mapSession(r) : null; }
  async updateSessionTokens(id: string, a: string, r: string, p: string, ae: number, re: number) { await this.db.prepare(`UPDATE sessions SET access_hash=?,refresh_hash=?,prev_refresh_hash=?,access_expires_at=?,refresh_expires_at=? WHERE id=?`).bind(a, r, p, ae, re, id).run(); }
  async revokeSession(id: string) { await this.db.prepare(`UPDATE sessions SET revoked=1 WHERE id=?`).bind(id).run(); }
  async revokeDeviceSessions(userId: string, deviceId: string) { await this.db.prepare(`UPDATE sessions SET revoked=1 WHERE user_id=? AND device_id=?`).bind(userId, deviceId).run(); }
  async revokeOtherSessions(userId: string, keepSessionId: string | null) { await this.db.prepare(`UPDATE sessions SET revoked=1 WHERE user_id=? AND id<>?`).bind(userId, keepSessionId ?? "").run(); }
  async addHistory(item: ItemRow, archivedAt: string) { await this.db.prepare(`INSERT INTO item_history (id,item_id,vault_id,revision,ciphertext_b64,wrapped_item_key_b64,deleted,updated_at,archived_at) VALUES (?,?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(), item.id, item.vaultId, item.revision, item.ciphertextB64, item.wrappedItemKeyB64, item.deleted, item.updatedAt, archivedAt).run(); }
  async listHistory(vaultId: string, itemId: string) { const { results } = await this.db.prepare(`SELECT item_id AS id, vault_id, '' AS user_id, '' AS type, revision, ciphertext_b64, wrapped_item_key_b64, deleted, updated_at FROM item_history WHERE vault_id=? AND item_id=? ORDER BY revision DESC LIMIT 50`).bind(vaultId, itemId).all<Record<string, unknown>>(); return results.map(mapItem); }
  async createAttachment(a: AttachmentRow) { await this.db.prepare(`INSERT INTO attachments (id,user_id,vault_id,size_bytes,created_at) VALUES (?,?,?,?,?)`).bind(a.id, a.userId, a.vaultId, a.sizeBytes, a.createdAt).run(); }
  async getAttachment(userId: string, id: string) { const r = await this.db.prepare(`SELECT * FROM attachments WHERE user_id=? AND id=?`).bind(userId, id).first<Record<string, unknown>>(); return r ? { id: r.id as string, userId: r.user_id as string, vaultId: r.vault_id as string, sizeBytes: r.size_bytes as number, createdAt: r.created_at as string } : null; }
  async deleteAttachment(userId: string, id: string) { await this.db.prepare(`DELETE FROM attachments WHERE user_id=? AND id=?`).bind(userId, id).run(); }
  async getItem(vaultId: string, itemId: string) { const r = await this.db.prepare(`SELECT * FROM items WHERE vault_id=? AND id=?`).bind(vaultId, itemId).first<Record<string, unknown>>(); return r ? mapItem(r) : null; }
  async upsertItem(i: ItemRow) { await this.db.prepare(`INSERT INTO items (id,vault_id,user_id,type,ciphertext_b64,wrapped_item_key_b64,revision,deleted,updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET type=excluded.type,ciphertext_b64=excluded.ciphertext_b64,wrapped_item_key_b64=excluded.wrapped_item_key_b64,revision=excluded.revision,deleted=excluded.deleted,updated_at=excluded.updated_at`).bind(i.id, i.vaultId, i.userId, i.type, i.ciphertextB64, i.wrappedItemKeyB64, i.revision, i.deleted, i.updatedAt).run(); }
  async listItemsSince(vaultId: string, sinceIso: string | null) { const { results } = sinceIso ? await this.db.prepare(`SELECT * FROM items WHERE vault_id=? AND updated_at>? ORDER BY updated_at ASC`).bind(vaultId, sinceIso).all<Record<string, unknown>>() : await this.db.prepare(`SELECT * FROM items WHERE vault_id=? ORDER BY updated_at ASC`).bind(vaultId).all<Record<string, unknown>>(); return results.map(mapItem); }
  async audit(userId: string | null, event: string, meta: string) { await this.db.prepare(`INSERT INTO audit_log (id,user_id,event,meta,created_at) VALUES (?,?,?,?,?)`).bind(crypto.randomUUID(), userId, event, meta, new Date().toISOString()).run(); }
}
