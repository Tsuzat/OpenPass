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
      await api(`/items/${item.id}`, "PUT", {
        type: item.type, ciphertextB64: item.ciphertextB64, wrappedItemKeyB64: item.wrappedItemKeyB64, revision: item.revision,
      }, true);
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
      out.push({ id: item.id, type: item.type, revision: item.revision, name: String(plaintext.name ?? "(unnamed)"), plaintext });
    } catch { /* skip undecryptable items rather than crashing the vault */ }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function createItem(type: string, plaintextFields: Record<string, unknown>): Promise<void> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  const id = uuid();
  const plaintext = { v: 1, type, favorite: false, folderId: null, tags: [], ...plaintextFields };
  const enc = await crypto.encryptItemJson(vaultKeyB64, id, plaintext);
  await offlineStore.putItem({
    id, type, ...enc, revision: 1, deleted: false, updatedAt: new Date().toISOString(), dirty: true,
  });
  if (!offline) await syncPending().catch(() => undefined);
}

export const createLoginItem = (name: string, username: string, password: string, uri: string) =>
  createItem("login", { name, username, password, uris: uri ? [{ uri, match: "domain" }] : [], notes: "", totpId: null, customFields: [] });

export const currentTotp = (secretB32: string) => crypto.totp(secretB32);
export const makePassword = (length = 20) => crypto.makePassword(length);
export const newTotpSecret = () => crypto.newTotpSecret();
