export interface UserRow {
  id: string; email: string; verifierHash: string;
  kdfSaltB64: string; kdfParamsJson: string;
  wrappedVaultKeyB64: string; recoveryWrappedVaultKeyB64: string;
  identityPublicKeyB64: string; wrappedIdentityPrivateKeyB64: string;
  recoveryVerifierHash: string;
  vaultId: string; createdAt: string;
}
export interface DeviceRow {
  userId: string; deviceId: string; name: string; platform: string;
  status: "approved" | "pending"; createdAt: string; lastSeenAt: string;
}
export interface SessionRow {
  id: string; userId: string; deviceId: string;
  accessHash: string; refreshHash: string; prevRefreshHash: string | null;
  accessExpiresAt: number; refreshExpiresAt: number; revoked: number; createdAt: string;
}
export interface AttachmentRow {
  id: string; userId: string; vaultId: string; sizeBytes: number; createdAt: string;
}

export interface ItemRow {
  id: string; vaultId: string; userId: string; type: string;
  ciphertextB64: string; wrappedItemKeyB64: string;
  revision: number; deleted: number; updatedAt: string;
}

export interface Store {
  getUserByEmail(email: string): Promise<UserRow | null>;
  getUserById(id: string): Promise<UserRow | null>;
  createUser(u: UserRow): Promise<void>;
  updateUserVerifier(userId: string, verifierHash: string, wrappedVaultKeyB64: string, recoveryWrappedVaultKeyB64: string, kdfSaltB64: string, kdfParamsJson: string): Promise<void>;
  getDevice(userId: string, deviceId: string): Promise<DeviceRow | null>;
  upsertDevice(d: DeviceRow): Promise<void>;
  listDevices(userId: string): Promise<DeviceRow[]>;
  listPendingDevices(userId: string): Promise<DeviceRow[]>;
  setDeviceStatus(userId: string, deviceId: string, status: "approved" | "pending"): Promise<void>;
  deleteDevice(userId: string, deviceId: string): Promise<void>;
  getDeviceStatus(deviceId: string): Promise<"approved" | "pending" | "unknown">;
  createSession(s: SessionRow): Promise<void>;
  getSessionByAccessHash(hash: string): Promise<SessionRow | null>;
  getSessionByRefreshHash(hash: string): Promise<SessionRow | null>;
  getSessionByPrevRefreshHash(hash: string): Promise<SessionRow | null>;
  updateSessionTokens(id: string, accessHash: string, refreshHash: string, prevRefreshHash: string, accessExpiresAt: number, refreshExpiresAt: number): Promise<void>;
  revokeSession(id: string): Promise<void>;
  revokeDeviceSessions(userId: string, deviceId: string): Promise<void>;
  revokeOtherSessions(userId: string, keepSessionId: string | null): Promise<void>;
  addHistory(item: ItemRow, archivedAt: string): Promise<void>;
  listHistory(vaultId: string, itemId: string): Promise<ItemRow[]>;
  createAttachment(a: AttachmentRow): Promise<void>;
  getAttachment(userId: string, id: string): Promise<AttachmentRow | null>;
  deleteAttachment(userId: string, id: string): Promise<void>;
  getItem(vaultId: string, itemId: string): Promise<ItemRow | null>;
  upsertItem(i: ItemRow): Promise<void>;
  listItemsSince(vaultId: string, sinceIso: string | null): Promise<ItemRow[]>;
  audit(userId: string | null, event: string, meta: string): Promise<void>;
}
