/** Server-side helpers. The server only ever handles the HKDF-derived AuthVerifier, never the master password/key. */

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function randomTokenB64(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return bytesToB64(b).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** PBKDF2-HMAC-SHA256 over the already-derived verifier. Format: pbkdf2$iter$saltB64$hashB64 */
export async function hashVerifier(verifierB64: string, iterations = 600_000): Promise<string> {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey("raw", b64ToBytes(verifierB64) as BufferSource, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" }, key, 256);
  return `pbkdf2$${iterations}$${bytesToB64(salt)}$${bytesToB64(new Uint8Array(bits))}`;
}

export async function verifyVerifier(verifierB64: string, stored: string): Promise<boolean> {
  try {
    const [, iterStr, saltB64, hashB64] = stored.split("$");
    const key = await crypto.subtle.importKey("raw", b64ToBytes(verifierB64) as BufferSource, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: b64ToBytes(saltB64) as BufferSource, iterations: Number(iterStr), hash: "SHA-256" }, key, 256);
    const expected = b64ToBytes(hashB64);
    const actual = new Uint8Array(bits);
    if (expected.length !== actual.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i]; // constant-time
    return diff === 0;
  } catch { return false; }
}

/** Deterministic fake KDF salt for unknown emails (anti-enumeration). */
export async function fakeSaltB64(email: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`openpass-fake-salt:${email.toLowerCase()}`));
  return bytesToB64(new Uint8Array(digest).slice(0, 16));
}
