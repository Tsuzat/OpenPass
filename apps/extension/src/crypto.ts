/* eslint-disable @typescript-eslint/no-explicit-any */
// Extension crypto: loads the Rust-core WASM package (copied into dist/wasm by the
// build script) from the extension origin. Same guarantee as the web vault:
// derive returns only AuthVerifier + KEK; the master key never materializes in JS.
declare const chrome: any;

let mod: any = null;

export async function loadCrypto(): Promise<any> {
  if (mod) return mod;
  const jsUrl = chrome.runtime.getURL("wasm/openpass_core.js");
  mod = await import(/* @vite-ignore */ jsUrl);
  await mod.default(chrome.runtime.getURL("wasm/openpass_core_bg.wasm"));
  return mod;
}

export interface KdfParams { memoryKib: number; iterations: number; parallelism: number; saltB64: string }

export async function derive(password: string, params: KdfParams): Promise<{ authVerifierB64: string; kekB64: string }> {
  const m = await loadCrypto();
  return JSON.parse(m.deriveAuthMaterial(password, JSON.stringify(params)));
}
export async function unwrapKey(wrapperB64: string, blobB64: string): Promise<string> {
  const m = await loadCrypto();
  return m.unwrapKeyB64(wrapperB64, blobB64);
}
export async function decryptItem(vaultKeyB64: string, itemId: string, ciphertextB64: string, wrappedItemKeyB64: string): Promise<any> {
  const m = await loadCrypto();
  return JSON.parse(m.decryptItem(vaultKeyB64, itemId, ciphertextB64, wrappedItemKeyB64));
}
