import * as crypto from "./crypto";
import { getServerUrl } from "./api";
import { offlineStore, type CachedItem } from "./offlineStore";

/** Vault session: the vault key exists ONLY in this module's memory. Lock = drop references. */
let vaultKeyB64: string | null = null;
let accessToken: string | null = null;
let offline = false;

export const isUnlocked = () => vaultKeyB64 !== null;
export const isOffline = () => offline;
export function lock() { vaultKeyB64 = null; accessToken = null; offline = false; }

const uuid = () => globalThis.crypto.randomUUID();
function deviceId(): string {
  let id = localStorage.getItem("openpass.deviceId");
  if (!id) { id = uuid(); localStorage.setItem("openpass.deviceId", id); }
  return id;
}

async function api(path: string, method = "GET", body?: unknown, auth = false): Promise<any> {
  let res: Response;
  try {
    res = await fetch(`${getServerUrl()}${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...(auth && accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch { const e = new Error("NETWORK") as Error & { code: string }; e.code = "NETWORK"; throw e; }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const code = (data as any)?.error?.code ?? `HTTP_${res.status}`;
    const e = new Error(code) as Error & { code: string; status: number };
    e.code = code; e.status = res.status;
    throw e;
  }
  return data;
}

export async function register(email: string, masterPassword: string): Promise<{ recoveryKeyText: string }> {
  const params = await crypto.newKdfParams();
  const auth = await crypto.derive(masterPassword, params);
  const vaultKey = await crypto.randomKey();
  vaultKeyB64 = vaultKey;
  const recovery = await crypto.newRecoveryKey();
  const { saltB64, ...kdfParams } = params;
  const wrappedVaultKeyB64 = await crypto.wrapKey(auth.kekB64, vaultKey);
  const recoveryWrappedVaultKeyB64 = await crypto.wrapKey(recovery.keyB64, vaultKey);
  const data = await api("/auth/register", "POST", {
    email, authVerifierB64: auth.authVerifierB64, kdfSaltB64: saltB64, kdfParams,
    wrappedVaultKeyB64, recoveryWrappedVaultKeyB64,
    recoveryAuthProofB64: await crypto.recoveryProof(recovery.keyB64),
    identityPublicKeyB64: await crypto.randomKey(), // placeholder: X25519 identity keypair lands with sharing (post-v1)
    wrappedIdentityPrivateKeyB64: await crypto.wrapKey(vaultKey, await crypto.randomKey()),
    device: { id: deviceId(), name: "Web Vault", platform: "web" },
  });
  accessToken = data.accessToken;
  offline = false;
  await offlineStore.clear();
  await offlineStore.saveSession({
    email: email.toLowerCase(), serverUrl: getServerUrl(), wrappedVaultKeyB64, recoveryWrappedVaultKeyB64,
    kdfSaltB64: saltB64, kdfParamsJson: JSON.stringify(kdfParams),
  });
  return { recoveryKeyText: recovery.text };
}

export async function login(email: string, masterPassword: string): Promise<{ offline: boolean }> {
  const cached = await offlineStore.loadSession();
  try {
    const pre = await api("/auth/prelogin", "POST", { email });
    const params = { ...pre.kdfParams, saltB64: pre.kdfSaltB64 } as crypto.KdfParams;
    const auth = await crypto.derive(masterPassword, params);
    const data = await api("/auth/login", "POST", {
      email, authVerifierB64: auth.authVerifierB64,
      device: { id: deviceId(), name: "Web Vault", platform: "web" },
    });
    accessToken = data.accessToken;
    vaultKeyB64 = await crypto.unwrapKey(auth.kekB64, data.wrappedVaultKeyB64);
    offline = false;
    await offlineStore.saveSession({
      email: email.toLowerCase(), serverUrl: getServerUrl(),
      wrappedVaultKeyB64: data.wrappedVaultKeyB64, recoveryWrappedVaultKeyB64: data.recoveryWrappedVaultKeyB64,
      kdfSaltB64: pre.kdfSaltB64, kdfParamsJson: JSON.stringify(pre.kdfParams),
    });
    await syncPending().catch(() => undefined);
    return { offline: false };
  } catch (e) {
    // Offline unlock: cached wrapped key + AEAD unwrap authenticates the password locally.
    if ((e as { code?: string }).code === "NETWORK" && cached && cached.email === email.toLowerCase() && cached.serverUrl === getServerUrl()) {
      const params = { ...(JSON.parse(cached.kdfParamsJson) as object), saltB64: cached.kdfSaltB64 } as crypto.KdfParams;
      const auth = await crypto.derive(masterPassword, params);
      vaultKeyB64 = await crypto.unwrapKey(auth.kekB64, cached.wrappedVaultKeyB64); // throws on wrong password
      accessToken = null;
      offline = true;
      return { offline: true };
    }
    throw e;
  }
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  if (!vaultKeyB64 || !accessToken) throw new Error("LOCKED");
  const cached = await offlineStore.loadSession();
  if (!cached) throw new Error("NO_CACHED_SESSION");
  const oldParams = { ...(JSON.parse(cached.kdfParamsJson) as object), saltB64: cached.kdfSaltB64 } as crypto.KdfParams;
  const current = await crypto.derive(currentPassword, oldParams);
  // sanity: current KEK must unwrap the cached vault key (rejects wrong current password locally)
  await crypto.unwrapKey(current.kekB64, cached.wrappedVaultKeyB64);

  const newParams = await crypto.newKdfParams();
  const next = await crypto.derive(newPassword, newParams);
  const { saltB64, ...kdfParams } = newParams;
  const wrappedVaultKeyB64 = await crypto.wrapKey(next.kekB64, vaultKeyB64);
  await api("/auth/change-password", "POST", {
    currentAuthVerifierB64: current.authVerifierB64, newAuthVerifierB64: next.authVerifierB64,
    kdfSaltB64: saltB64, kdfParams, wrappedVaultKeyB64,
  }, true);
  await offlineStore.saveSession({ ...cached, wrappedVaultKeyB64, kdfSaltB64: saltB64, kdfParamsJson: JSON.stringify(kdfParams) });
}

/** Forgot-password recovery: recovery key -> proof -> unwrap vault -> set a new master password. */
export async function recoverWithRecoveryKey(email: string, recoveryKeyText: string, newPassword: string): Promise<void> {
  const recoveryKeyB64 = await crypto.parseRecovery(recoveryKeyText);
  const proof = await crypto.recoveryProof(recoveryKeyB64);
  const info = await api("/auth/recovery-info", "POST", { email, recoveryAuthProofB64: proof });
  const vaultKey = await crypto.unwrapKey(recoveryKeyB64, info.recoveryWrappedVaultKeyB64);
  const newParams = await crypto.newKdfParams();
  const next = await crypto.derive(newPassword, newParams);
  const { saltB64, ...kdfParams } = newParams;
  await api("/auth/recover", "POST", {
    email, recoveryAuthProofB64: proof, newAuthVerifierB64: next.authVerifierB64,
    kdfSaltB64: saltB64, kdfParams,
    wrappedVaultKeyB64: await crypto.wrapKey(next.kekB64, vaultKey),
    recoveryWrappedVaultKeyB64: await crypto.wrapKey(recoveryKeyB64, vaultKey),
  });
  await login(email, newPassword);
}

export interface VaultItemSummary { id: string; type: string; revision: number; name: string; plaintext: Record<string, any> }

async function pullMerge(): Promise<void> {
  const since = await offlineStore.getCursor();
  const data = await api(`/items${since ? `?since=${encodeURIComponent(since)}` : ""}`, "GET", undefined, true);
  const rows: CachedItem[] = (data.items as any[]).map((i) => ({ ...i, dirty: false }));
  // Never clobber a locally dirty item with a stale server copy; syncPending resolves order.
  const local = new Map((await offlineStore.allItems()).map((i) => [i.id, i]));
  await offlineStore.putItems(rows.filter((r) => !local.get(r.id)?.dirty));
  if (data.cursor) await offlineStore.setCursor(data.cursor);
}

export async function syncPending(): Promise<void> {
  if (!accessToken) return;
  for (const item of await offlineStore.dirtyItems()) {
    try {
      if (item.deleted) {
        await api(`/items/${item.id}`, "DELETE", undefined, true);
      } else {
        await api(`/items/${item.id}`, "PUT", {
          type: item.type, ciphertextB64: item.ciphertextB64, wrappedItemKeyB64: item.wrappedItemKeyB64, revision: item.revision,
        }, true);
      }
      await offlineStore.putItem({ ...item, dirty: false });
    } catch (e) {
      if ((e as { code?: string }).code === "NETWORK") return; // still offline; retry next unlock/pull
      throw e;
    }
  }
}

export async function listItems(): Promise<VaultItemSummary[]> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  if (!offline && accessToken) {
    try { await syncPending(); await pullMerge(); }
    catch (e) { if ((e as { code?: string }).code !== "NETWORK") throw e; offline = true; }
  }
  const out: VaultItemSummary[] = [];
  for (const item of await offlineStore.allItems()) {
    if (item.deleted) continue;
    try {
      const plaintext = await crypto.decryptItemJson<Record<string, any>>(vaultKeyB64, item.id, item);
      if (plaintext.system) continue; // internal system items (folders etc.) are not vault entries
      out.push({ id: item.id, type: item.type, revision: item.revision, name: String(plaintext.name ?? "(unnamed)"), plaintext });
    } catch { /* skip undecryptable items rather than crashing the vault */ }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function createItem(type: string, plaintextFields: Record<string, unknown>): Promise<string> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  const id = uuid();
  const plaintext = { v: 1, type, favorite: false, folderId: null, tags: [], ...plaintextFields };
  const enc = await crypto.encryptItemJson(vaultKeyB64, id, plaintext);
  await offlineStore.putItem({
    id, type, ...enc, revision: 1, deleted: false, updatedAt: new Date().toISOString(), dirty: true,
  });
  if (!offline) await syncPending().catch(() => undefined);
  return id;
}

// ---------- Folders ----------
// Folder definitions live in a dedicated encrypted system item, so folder names
// sync end-to-end and never reach the server in plaintext. System items are
// hidden from the item list.

export interface Folder { id: string; name: string }
const FOLDER_SYSTEM = "folders";

async function findSystemItem(): Promise<{ summary: VaultItemSummary } | null> {
  if (!vaultKeyB64) return null;
  for (const item of await offlineStore.allItems()) {
    if (item.deleted) continue;
    try {
      const plaintext = await crypto.decryptItemJson<Record<string, any>>(vaultKeyB64, item.id, item);
      if (plaintext.system === FOLDER_SYSTEM) {
        return { summary: { id: item.id, type: item.type, revision: item.revision, name: String(plaintext.name ?? ""), plaintext } };
      }
    } catch { /* skip */ }
  }
  return null;
}

export async function getFolders(): Promise<Folder[]> {
  const found = await findSystemItem();
  const folders = found?.summary.plaintext.folders;
  return Array.isArray(folders) ? (folders as Folder[]) : [];
}

export async function setFolders(folders: Folder[]): Promise<void> {
  const found = await findSystemItem();
  if (found) {
    await updateItem(found.summary, { folders, content: "" });
  } else {
    await createItem("secure_note", { name: "__openpass_folders__", system: FOLDER_SYSTEM, folders, content: "" });
  }
}

export async function updateItem(item: VaultItemSummary, fields: Record<string, unknown>): Promise<void> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  const cached = (await offlineStore.allItems()).find((i) => i.id === item.id);
  if (!cached) throw new Error("NOT_FOUND");
  const plaintext = { ...item.plaintext, ...fields, v: 1, type: item.type };
  const enc = await crypto.encryptItemJson(vaultKeyB64, item.id, plaintext);
  // Unsynced (dirty) items collapse edits into the pending revision; synced items bump it.
  const revision = cached.dirty ? cached.revision : cached.revision + 1;
  await offlineStore.putItem({ ...cached, ...enc, revision, updatedAt: new Date().toISOString(), dirty: true });
  if (!offline) await syncPending().catch(() => undefined);
}

export async function listTrash(): Promise<VaultItemSummary[]> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  if (!offline && accessToken) {
    try { await pullMerge(); } catch { /* serve from cache */ }
  }
  const out: VaultItemSummary[] = [];
  for (const item of await offlineStore.allItems()) {
    if (!item.deleted) continue;
    try {
      const plaintext = await crypto.decryptItemJson<Record<string, any>>(vaultKeyB64, item.id, item);
      if (plaintext.system) continue;
      out.push({ id: item.id, type: item.type, revision: item.revision, name: String(plaintext.name ?? "(unnamed)"), plaintext });
    } catch { /* skip */ }
  }
  return out;
}

export async function restoreItem(id: string): Promise<void> {
  const cached = (await offlineStore.allItems()).find((i) => i.id === id);
  if (!cached || !cached.deleted) return;
  await offlineStore.putItem({ ...cached, deleted: false, revision: cached.revision + 1, dirty: true, updatedAt: new Date().toISOString() });
  if (!offline) await syncPending().catch(() => undefined);
}

/** Local purge: removes the row on this device. The server tombstone remains, by design. */
export async function purgeItem(id: string): Promise<void> {
  await offlineStore.removeItem(id);
}

export interface HistoryEntry { revision: number; updatedAt: string; plaintext: Record<string, any> }

export async function getItemHistory(id: string): Promise<HistoryEntry[]> {
  if (!vaultKeyB64 || !accessToken) throw new Error("LOCKED");
  const data = await api(`/items/${id}/history`, "GET", undefined, true);
  const out: HistoryEntry[] = [];
  for (const h of data.history as any[]) {
    try {
      const plaintext = await crypto.decryptItemJson<Record<string, any>>(vaultKeyB64, id, h);
      out.push({ revision: h.revision, updatedAt: h.updatedAt, plaintext });
    } catch { /* skip */ }
  }
  return out;
}

export async function restoreHistoryVersion(id: string, entry: HistoryEntry): Promise<void> {
  const cached = (await offlineStore.allItems()).find((i) => i.id === id);
  if (!cached || !vaultKeyB64) throw new Error("NOT_FOUND");
  const enc = await crypto.encryptItemJson(vaultKeyB64, id, entry.plaintext);
  const revision = cached.dirty ? cached.revision : cached.revision + 1;
  await offlineStore.putItem({ ...cached, ...enc, revision, deleted: false, dirty: true, updatedAt: new Date().toISOString() });
  if (!offline) await syncPending().catch(() => undefined);
}

export async function deleteItem(id: string): Promise<void> {
  const cached = (await offlineStore.allItems()).find((i) => i.id === id);
  if (!cached) return;
  // Never synced: dropping the local row is enough, no tombstone needed.
  if (cached.dirty && cached.revision === 1) { await offlineStore.removeItem(id); return; }
  await offlineStore.putItem({ ...cached, deleted: true, dirty: true, updatedAt: new Date().toISOString() });
  if (!offline) await syncPending().catch(() => undefined);
}

export const createLoginItem = (name: string, username: string, password: string, uri: string) =>
  createItem("login", { name, username, password, uris: uri ? [{ uri, match: "domain" }] : [], notes: "", totpId: null, customFields: [] });

// ---------- Devices ----------

export interface DeviceInfoRow { deviceId: string; name: string; platform: string; status: string; createdAt: string; lastSeenAt: string; current?: boolean }

export async function listDevices(): Promise<DeviceInfoRow[]> {
  if (!accessToken) throw new Error("LOCKED");
  const data = await api("/devices", "GET", undefined, true);
  return data.devices as DeviceInfoRow[];
}
export async function listPendingDevices(): Promise<DeviceInfoRow[]> {
  if (!accessToken) throw new Error("LOCKED");
  const data = await api("/devices/pending", "GET", undefined, true);
  return data.devices as DeviceInfoRow[];
}
export async function approveDevice(deviceId: string): Promise<void> {
  if (!accessToken) throw new Error("LOCKED");
  await api(`/devices/${deviceId}/approve`, "POST", {}, true);
}
export async function revokeDevice(deviceId: string): Promise<void> {
  if (!accessToken) throw new Error("LOCKED");
  await api(`/devices/${deviceId}`, "DELETE", undefined, true);
}

// ---------- Files (Phase 3: chunked-AEAD blobs in R2) ----------

export async function uploadFile(fileName: string, mimeType: string, bytes: Uint8Array): Promise<void> {
  if (!vaultKeyB64 || !accessToken) throw new Error("LOCKED");
  const fileKey = await crypto.randomKey();
  const ciphertextB64 = await crypto.encryptFileBytes(fileKey, bytes);
  const upload = await fetch(`${getServerUrl()}/attachments`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/octet-stream" },
    body: Uint8Array.from(atob(ciphertextB64), (ch) => ch.charCodeAt(0)) as BodyInit,
  });
  if (!upload.ok) throw new Error(`UPLOAD_FAILED_${upload.status}`);
  const { id: attachmentId } = (await upload.json()) as { id: string };
  await createItem("file", {
    name: fileName, fileName, mimeType: mimeType || "application/octet-stream",
    sizeBytes: bytes.length, attachmentId,
    wrappedFileKeyB64: await crypto.wrapKey(vaultKeyB64, fileKey),
  });
}

export async function downloadFile(item: VaultItemSummary): Promise<{ fileName: string; mimeType: string; bytes: Uint8Array }> {
  if (!vaultKeyB64 || !accessToken) throw new Error("LOCKED");
  const attachmentId = String(item.plaintext.attachmentId ?? "");
  const res = await fetch(`${getServerUrl()}/attachments/${attachmentId}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`DOWNLOAD_FAILED_${res.status}`);
  const cipherBytes = new Uint8Array(await res.arrayBuffer());
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < cipherBytes.length; i += CHUNK) bin += String.fromCharCode(...cipherBytes.subarray(i, i + CHUNK));
  const fileKey = await crypto.unwrapKey(vaultKeyB64, String(item.plaintext.wrappedFileKeyB64 ?? ""));
  const bytes = await crypto.decryptFileBytes(fileKey, btoa(bin));
  return { fileName: String(item.plaintext.fileName ?? item.name), mimeType: String(item.plaintext.mimeType ?? "application/octet-stream"), bytes };
}

// ---------- Encrypted export / import ----------

const EXPORT_AAD = "openpass/export/v1";

export async function exportEncrypted(exportPassword: string): Promise<string> {
  const items = await listItems();
  const plaintexts = items.map((i) => i.plaintext);
  const { params, keyB64 } = await crypto.standaloneKey(exportPassword);
  const ciphertextB64 = await crypto.encryptTextWithKey(keyB64, JSON.stringify(plaintexts), EXPORT_AAD);
  return JSON.stringify({ format: "openpass-export", version: 1, kdfParams: params, ciphertextB64 }, null, 2);
}

export interface ImportReport { total: number; imported: number; skippedDuplicates: number }

export async function previewImport(items: Record<string, unknown>[]): Promise<{ fresh: Record<string, unknown>[]; duplicates: Record<string, unknown>[] }> {
  const { dedupeKey, partitionDuplicates } = await import("./import");
  const existing = await listItems();
  const existingKeys = new Set(existing.map((i) => dedupeKey({
    type: i.type, name: i.name,
    username: i.plaintext.username, uris: i.plaintext.uris,
  })));
  return partitionDuplicates(items, existingKeys);
}

export async function importItems(items: Record<string, unknown>[], skipDuplicates = true): Promise<ImportReport> {
  const { fresh, duplicates } = skipDuplicates ? await previewImport(items) : { fresh: items, duplicates: [] as Record<string, unknown>[] };
  for (const item of fresh) {
    const { type, ...fields } = item as { type: string };
    await createItem(String(type), fields);
  }
  return { total: items.length, imported: fresh.length, skippedDuplicates: duplicates.length };
}

export async function importEncryptedExport(text: string, exportPassword: string): Promise<ImportReport> {
  const data = JSON.parse(text) as { format?: string; kdfParams: crypto.KdfParams; ciphertextB64: string };
  if (data.format !== "openpass-export") throw new Error("Not an OpenPass encrypted export");
  const keyB64 = await crypto.keyWithParams(exportPassword, data.kdfParams);
  const json = await crypto.decryptTextWithKey(keyB64, data.ciphertextB64, EXPORT_AAD);
  return importItems(JSON.parse(json) as Record<string, unknown>[]);
}

export async function exportPlaintextJson(): Promise<string> {
  const items = await listItems();
  return JSON.stringify({ format: "openpass-plaintext-export", version: 1, items: items.map((i) => i.plaintext) }, null, 2);
}

export async function createPasskeyItem(name: string, rpId: string, userName: string): Promise<void> {
  const kp = await crypto.generatePasskey();
  const credentialIdB64 = await crypto.randomKey();
  await createItem("passkey", {
    name, rpId, rpName: rpId, userName, credentialIdB64,
    privateKeyPkcs8B64: kp.privateKeyPkcs8B64, counter: 0,
  });
}

export const currentTotp = (secretB32: string) => crypto.totp(secretB32);
export const makePassword = (length = 20) => crypto.makePassword(length);
export const newTotpSecret = () => crypto.newTotpSecret();
