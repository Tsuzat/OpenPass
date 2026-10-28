import type { DeviceRow, ItemRow, SessionRow, Store, UserRow } from "./types";

/** In-memory store for tests and local dev. Production uses D1Store with identical semantics. */
export class MemoryStore implements Store {
  users = new Map<string, UserRow>();
  devices = new Map<string, DeviceRow>();
  sessions = new Map<string, SessionRow>();
  items = new Map<string, ItemRow>();
  audits: { userId: string | null; event: string; meta: string }[] = [];

  async getUserByEmail(email: string) { return [...this.users.values()].find((u) => u.email === email) ?? null; }
  async getUserById(id: string) { return this.users.get(id) ?? null; }
  async createUser(u: UserRow) { this.users.set(u.id, u); }
  async updateUserVerifier(userId: string, verifierHash: string, wrappedVaultKeyB64: string, recoveryWrappedVaultKeyB64: string, kdfSaltB64: string, kdfParamsJson: string) {
    const u = this.users.get(userId); if (u) Object.assign(u, { verifierHash, wrappedVaultKeyB64, recoveryWrappedVaultKeyB64, kdfSaltB64, kdfParamsJson });
  }
  async getDevice(userId: string, deviceId: string) { return this.devices.get(`${userId}:${deviceId}`) ?? null; }
  async upsertDevice(d: DeviceRow) { this.devices.set(`${d.userId}:${d.deviceId}`, d); }
  async listDevices(userId: string) { return [...this.devices.values()].filter((d) => d.userId === userId); }
  async listPendingDevices(userId: string) { return (await this.listDevices(userId)).filter((d) => d.status === "pending"); }
  async setDeviceStatus(userId: string, deviceId: string, status: "approved" | "pending") {
    const d = await this.getDevice(userId, deviceId); if (d) d.status = status;
  }
  async deleteDevice(userId: string, deviceId: string) { this.devices.delete(`${userId}:${deviceId}`); }
  async getDeviceStatus(deviceId: string) {
    const d = [...this.devices.values()].find((x) => x.deviceId === deviceId);
    return d ? d.status : "unknown";
  }
  async createSession(s: SessionRow) { this.sessions.set(s.id, s); }
  async getSessionByAccessHash(hash: string) { return [...this.sessions.values()].find((s) => s.accessHash === hash) ?? null; }
  async getSessionByRefreshHash(hash: string) { return [...this.sessions.values()].find((s) => s.refreshHash === hash) ?? null; }
  async getSessionByPrevRefreshHash(hash: string) { return [...this.sessions.values()].find((s) => s.prevRefreshHash === hash) ?? null; }
  async updateSessionTokens(id: string, accessHash: string, refreshHash: string, prevRefreshHash: string, accessExpiresAt: number, refreshExpiresAt: number) {
    const s = this.sessions.get(id); if (s) Object.assign(s, { accessHash, refreshHash, prevRefreshHash, accessExpiresAt, refreshExpiresAt });
  }
  async revokeSession(id: string) { const s = this.sessions.get(id); if (s) s.revoked = 1; }
  async revokeDeviceSessions(userId: string, deviceId: string) {
    for (const s of this.sessions.values()) if (s.userId === userId && s.deviceId === deviceId) s.revoked = 1;
  }
  async getItem(vaultId: string, itemId: string) { return this.items.get(`${vaultId}:${itemId}`) ?? null; }
  async upsertItem(i: ItemRow) { this.items.set(`${i.vaultId}:${i.id}`, i); }
  async listItemsSince(vaultId: string, sinceIso: string | null) {
    return [...this.items.values()].filter((i) => i.vaultId === vaultId && (!sinceIso || i.updatedAt > sinceIso))
      .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt));
  }
  async audit(userId: string | null, event: string, meta: string) { this.audits.push({ userId, event, meta }); }
}
