import * as crypto from "./crypto";
import { getServerUrl } from "./api";

/** Vault session: vault key exists ONLY in this module's memory. Lock = drop references. */
let vaultKeyB64: string | null = null;
let accessToken: string | null = null;

export const isUnlocked = () => vaultKeyB64 !== null;
export function lock() { vaultKeyB64 = null; accessToken = null; }

const uuid = () => globalThis.crypto.randomUUID();
function deviceId(): string {
  let id = localStorage.getItem("openpass.deviceId");
  if (!id) { id = uuid(); localStorage.setItem("openpass.deviceId", id); }
  return id;
}

async function api(path: string, method = "GET", body?: unknown, auth = false): Promise<any> {
  const res = await fetch(`${getServerUrl()}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(auth && accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const code = (data as any)?.error?.code ?? `HTTP_${res.status}`;
    const e = new Error(code) as Error & { code: string; status: number };
    e.code = code; e.status = res.status;
    throw e;
  }
  return data;
}

export interface RegisterResult { recoveryKeyText: string }

export async function register(email: string, masterPassword: string): Promise<RegisterResult> {
  const params = await crypto.newKdfParams();
  const auth = await crypto.derive(masterPassword, params);
  const vaultKey = await crypto.randomKey();
  vaultKeyB64 = vaultKey;
  const recovery = await crypto.newRecoveryKey();
  const { saltB64, ...kdfParams } = params;
  const data = await api("/auth/register", "POST", {
    email,
    authVerifierB64: auth.authVerifierB64,
    kdfSaltB64: saltB64,
    kdfParams,
    wrappedVaultKeyB64: await crypto.wrapKey(auth.kekB64, vaultKey),
    recoveryWrappedVaultKeyB64: await crypto.wrapKey(recovery.keyB64, vaultKey),
    identityPublicKeyB64: await crypto.randomKey(), // placeholder: X25519 identity keypair lands with sharing (post-v1)
    wrappedIdentityPrivateKeyB64: await crypto.wrapKey(vaultKey, await crypto.randomKey()),
    device: { id: deviceId(), name: "Web Vault", platform: "web" },
  });
  accessToken = data.accessToken;
  return { recoveryKeyText: recovery.text };
}

export async function login(email: string, masterPassword: string): Promise<void> {
  const pre = await api("/auth/prelogin", "POST", { email });
  const params = { ...pre.kdfParams, saltB64: pre.kdfSaltB64 } as crypto.KdfParams;
  const auth = await crypto.derive(masterPassword, params);
  const data = await api("/auth/login", "POST", {
    email, authVerifierB64: auth.authVerifierB64,
    device: { id: deviceId(), name: "Web Vault", platform: "web" },
  });
  accessToken = data.accessToken;
  vaultKeyB64 = await crypto.unwrapKey(auth.kekB64, data.wrappedVaultKeyB64);
}

export interface VaultItemSummary { id: string; type: string; revision: number; name: string; plaintext: Record<string, unknown> }

export async function listItems(): Promise<VaultItemSummary[]> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  const data = await api("/items", "GET", undefined, true);
  const out: VaultItemSummary[] = [];
  for (const item of data.items as any[]) {
    if (item.deleted) continue;
    try {
      const plaintext = await crypto.decryptItemJson<Record<string, any>>(vaultKeyB64, item.id, item);
      out.push({ id: item.id, type: item.type, revision: item.revision, name: String(plaintext.name ?? "(unnamed)"), plaintext });
    } catch { /* skip undecryptable items rather than crashing the vault */ }
  }
  return out;
}

export async function createLoginItem(name: string, username: string, password: string, uri: string): Promise<void> {
  if (!vaultKeyB64) throw new Error("LOCKED");
  const id = uuid();
  const plaintext = {
    v: 1, type: "login", name, username, password,
    uris: uri ? [{ uri, match: "domain" }] : [],
    notes: "", favorite: false, folderId: null, tags: [], totpId: null, customFields: [],
  };
  const enc = await crypto.encryptItemJson(vaultKeyB64, id, plaintext);
  await api(`/items/${id}`, "PUT", { type: "login", ...enc, revision: 1 }, true);
}

export async function currentTotp(secretB32: string): Promise<string> {
  return crypto.totp(secretB32);
}
