/* tslint:disable */
/* eslint-disable */

export function decryptItem(vault_key_b64: string, item_id: string, ciphertext_b64: string, wrapped_item_key_b64: string): string;

/**
 * Argon2id(password) -> { authVerifierB64, kekB64 }. Runs synchronously; call from a Web Worker.
 */
export function deriveAuthMaterial(password: string, params_json: string): string;

export function encryptItem(vault_key_b64: string, item_id: string, plaintext_utf8: string): string;

export function generateKdfParams(): string;

export function generatePassword(length: number): string;

export function generateRecoveryKey(): string;

export function generateTotpSecretB32(): string;

export function parseRecoveryKey(text: string): string;

export function randomKeyB64(): string;

export function totpAt(secret_b32: string, unix_seconds: bigint, period: bigint, digits: number, sha256: boolean): string;

export function unwrapKeyB64(wrapper_b64: string, blob_b64: string): string;

export function wrapKeyB64(wrapper_b64: string, key_b64: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decryptItem: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly deriveAuthMaterial: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encryptItem: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly generateKdfParams: () => [number, number, number, number];
    readonly generatePassword: (a: number) => [number, number];
    readonly generateRecoveryKey: () => [number, number, number, number];
    readonly generateTotpSecretB32: () => [number, number];
    readonly parseRecoveryKey: (a: number, b: number) => [number, number, number, number];
    readonly randomKeyB64: () => [number, number];
    readonly totpAt: (a: number, b: number, c: bigint, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly unwrapKeyB64: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wrapKeyB64: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
