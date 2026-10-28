/**
 * Web crypto facade over the Rust core compiled to WASM.
 * In browsers, all operations run in a Web Worker (crypto.worker.ts) so Argon2id
 * never blocks the UI. Outside browsers (tests), the same WASM module is called directly.
 * The master key never enters JS: derive returns only AuthVerifier + KEK.
 */
import init, {
  deriveAuthMaterial, generateKdfParams, randomKeyB64, wrapKeyB64, unwrapKeyB64,
  encryptItem, decryptItem, generateRecoveryKey, parseRecoveryKey, recoveryAuthProof, totpAt, generatePassword,
  generateTotpSecretB32,
} from "./wasm/openpass_core.js";
import wasmUrl from "./wasm/openpass_core_bg.wasm?url";

export interface KdfParams { memoryKib: number; iterations: number; parallelism: number; saltB64: string }
export interface AuthMaterial { authVerifierB64: string; kekB64: string }
export interface EncryptedItemPayload { ciphertextB64: string; wrappedItemKeyB64: string }

// ---------- direct (non-browser / test) path ----------
let directReady: Promise<void> | null = null;
function ensureDirect(): Promise<void> {
  if (!directReady) directReady = init().then(() => undefined);
  return directReady;
}

// ---------- worker path ----------
const useWorker = typeof window !== "undefined" && typeof Worker !== "undefined";
let worker: Worker | null = null;
let nextId = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function callWorker<T>(op: string, ...args: unknown[]): Promise<T> {
  if (!worker) {
    worker = new Worker(new URL("./crypto.worker.ts", import.meta.url), { type: "module" });
    worker.addEventListener("message", (e: MessageEvent<{ id: number; ok: boolean; result?: unknown; error?: string }>) => {
      const p = pending.get(e.data.id);
      if (!p) return;
      pending.delete(e.data.id);
      if (e.data.ok) p.resolve(e.data.result);
      else p.reject(new Error(e.data.error ?? "worker error"));
    });
  }
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: (v) => resolve(v as T), reject });
    worker!.postMessage({ id, op, args, wasmUrl });
  });
}

async function call<T>(op: string, direct: () => T | Promise<T>, ...args: unknown[]): Promise<T> {
  if (useWorker) return callWorker<T>(op, ...args);
  await ensureDirect();
  return direct();
}

export async function newKdfParams(): Promise<KdfParams> {
  const s = await call("generateKdfParams", () => generateKdfParams());
  return JSON.parse(s as string) as KdfParams;
}
export async function derive(password: string, params: KdfParams): Promise<AuthMaterial> {
  const s = await call("derive", () => deriveAuthMaterial(password, JSON.stringify(params)), password, JSON.stringify(params));
  return JSON.parse(s as string) as AuthMaterial;
}
export async function randomKey(): Promise<string> {
  return call("randomKey", () => randomKeyB64());
}
export async function wrapKey(wrapperB64: string, keyB64: string): Promise<string> {
  return call("wrapKey", () => wrapKeyB64(wrapperB64, keyB64), wrapperB64, keyB64);
}
export async function unwrapKey(wrapperB64: string, blobB64: string): Promise<string> {
  return call("unwrapKey", () => unwrapKeyB64(wrapperB64, blobB64), wrapperB64, blobB64);
}
export async function encryptItemJson(vaultKeyB64: string, itemId: string, plaintext: unknown): Promise<EncryptedItemPayload> {
  const pt = JSON.stringify(plaintext);
  const s = await call("encryptItem", () => encryptItem(vaultKeyB64, itemId, pt), vaultKeyB64, itemId, pt);
  return JSON.parse(s as string) as EncryptedItemPayload;
}
export async function decryptItemJson<T>(vaultKeyB64: string, itemId: string, item: EncryptedItemPayload): Promise<T> {
  const s = await call("decryptItem", () => decryptItem(vaultKeyB64, itemId, item.ciphertextB64, item.wrappedItemKeyB64),
    vaultKeyB64, itemId, item.ciphertextB64, item.wrappedItemKeyB64);
  return JSON.parse(s as string) as T;
}
export async function newRecoveryKey(): Promise<{ text: string; keyB64: string }> {
  const s = await call("generateRecoveryKey", () => generateRecoveryKey());
  return JSON.parse(s as string) as { text: string; keyB64: string };
}
export async function parseRecovery(text: string): Promise<string> {
  return call("parseRecoveryKey", () => parseRecoveryKey(text), text);
}
export async function recoveryProof(recoveryKeyB64: string): Promise<string> {
  return call("recoveryAuthProof", () => recoveryAuthProof(recoveryKeyB64), recoveryKeyB64);
}
export async function totp(secretB32: string, atSeconds = Math.floor(Date.now() / 1000), digits = 6, sha256 = false): Promise<string> {
  return call("totpAt", () => totpAt(secretB32, BigInt(atSeconds), 30n, digits, sha256), secretB32, String(atSeconds), digits, sha256);
}
export async function makePassword(length = 20): Promise<string> {
  return call("generatePassword", () => generatePassword(length), length);
}
export async function newTotpSecret(): Promise<string> {
  return call("generateTotpSecretB32", () => generateTotpSecretB32());
}
