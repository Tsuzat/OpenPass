/**
 * Crypto Web Worker: Argon2id (64 MiB) and all AEAD operations run off the main thread.
 * Protocol: { id, op, args } -> { id, ok, result | error }
 * The master key never enters this worker either — derive returns verifier + KEK only.
 */
import init, {
  deriveAuthMaterial, generateKdfParams, randomKeyB64, wrapKeyB64, unwrapKeyB64,
  encryptItem, decryptItem, generatePasskeyKeypair, passkeySign, encryptBytesB64, decryptBytesB64, encryptFileB64, decryptFileB64, deriveStandaloneKey, deriveKeyWithParams, generateRecoveryKey, parseRecoveryKey, recoveryAuthProof, totpAt, generatePassword,
  generateTotpSecretB32,
} from "./wasm/openpass_core.js";

let ready: Promise<void> | null = null;

type Msg = { id: number; op: string; args: unknown[]; wasmUrl?: string };

const ops: Record<string, (...args: never[]) => unknown> = {
  generateKdfParams: () => generateKdfParams(),
  derive: (password: string, paramsJson: string) => deriveAuthMaterial(password, paramsJson),
  randomKey: () => randomKeyB64(),
  wrapKey: (w: string, k: string) => wrapKeyB64(w, k),
  unwrapKey: (w: string, b: string) => unwrapKeyB64(w, b),
  encryptItem: (vk: string, id: string, pt: string) => encryptItem(vk, id, pt),
  decryptItem: (vk: string, id: string, ct: string, wk: string) => decryptItem(vk, id, ct, wk),
  generatePasskeyKeypair: () => generatePasskeyKeypair(),
  passkeySign: (k: string, d: string) => passkeySign(k, d),
  encryptBytesB64: (k: string, pt: string, aad: string) => encryptBytesB64(k, pt, aad),
  decryptBytesB64: (k: string, b: string, aad: string) => decryptBytesB64(k, b, aad),
  encryptFileB64: (k: string, pt: string) => encryptFileB64(k, pt),
  decryptFileB64: (k: string, b: string) => decryptFileB64(k, b),
  deriveStandaloneKey: (pw: string) => deriveStandaloneKey(pw),
  deriveKeyWithParams: (pw: string, p: string) => deriveKeyWithParams(pw, p),
  generateRecoveryKey: () => generateRecoveryKey(),
  parseRecoveryKey: (t: string) => parseRecoveryKey(t),
  recoveryAuthProof: (k: string) => recoveryAuthProof(k),
  totpAt: (s: string, at: string, digits: number, sha256: boolean) => totpAt(s, BigInt(at), 30n, digits, sha256),
  generatePassword: (len: number) => generatePassword(len),
  generateTotpSecretB32: () => generateTotpSecretB32(),
};

self.addEventListener("message", async (e: MessageEvent<Msg>) => {
  const { id, op, args, wasmUrl } = e.data;
  try {
    if (!ready) ready = init(wasmUrl ? { module_or_path: wasmUrl } : undefined).then(() => undefined);
    await ready;
    const fn = ops[op];
    if (!fn) throw new Error(`unknown op: ${op}`);
    const result = (fn as (...a: unknown[]) => unknown)(...args);
    (self as unknown as { postMessage: (m: unknown) => void }).postMessage({ id, ok: true, result });
  } catch (err) {
    (self as unknown as { postMessage: (m: unknown) => void }).postMessage({ id, ok: false, error: String(err instanceof Error ? err.message : err) });
  }
});
