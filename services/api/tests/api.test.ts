import { describe, expect, test } from "bun:test";
import { createApp } from "../src/app";
import { MemoryStore } from "../src/store/memory";

const VERIFIER = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");
const deviceA = { id: crypto.randomUUID(), name: "MacBook", platform: "macos" as const };
const deviceB = { id: crypto.randomUUID(), name: "Pixel", platform: "android" as const };

function setup() {
  return createApp(new MemoryStore(), { pbkdf2Iterations: 1_000 }); // low iterations for test speed only
}
async function req(app: ReturnType<typeof setup>, path: string, method: string, body?: unknown, token?: string) {
  const res = await app.request(path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: (await res.json()) as any };
}
const registerBody = (device = deviceA) => ({
  email: "User@Example.com", authVerifierB64: VERIFIER,
  kdfSaltB64: Buffer.from("0123456789abcdef").toString("base64"),
  kdfParams: { memoryKib: 65536, iterations: 3, parallelism: 4 },
  wrappedVaultKeyB64: "wrapped==", recoveryWrappedVaultKeyB64: "recovery==",
  identityPublicKeyB64: "pub==", wrappedIdentityPrivateKeyB64: "priv==", device,
});

describe("auth + device approval", () => {
  test("register → login on same device → tokens work", async () => {
    const app = setup();
    const reg = await req(app, "/auth/register", "POST", registerBody());
    expect(reg.status).toBe(201);
    expect(reg.json.accessToken).toBeTruthy();

    const pre = await req(app, "/auth/prelogin", "POST", { email: "user@example.com" });
    expect(pre.json.kdfSaltB64).toBe(registerBody().kdfSaltB64);

    const login = await req(app, "/auth/login", "POST", { email: "user@example.com", authVerifierB64: VERIFIER, device: deviceA });
    expect(login.status).toBe(200);
    expect(login.json.wrappedVaultKeyB64).toBe("wrapped==");

    const vault = await req(app, "/vault", "GET", undefined, login.json.accessToken);
    expect(vault.status).toBe(200);
  });

  test("wrong verifier rejected; unknown email gets fake prelogin", async () => {
    const app = setup();
    await req(app, "/auth/register", "POST", registerBody());
    const bad = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");
    const login = await req(app, "/auth/login", "POST", { email: "user@example.com", authVerifierB64: bad, device: deviceA });
    expect(login.status).toBe(401);

    const fake1 = await req(app, "/auth/prelogin", "POST", { email: "ghost@example.com" });
    const fake2 = await req(app, "/auth/prelogin", "POST", { email: "ghost@example.com" });
    expect(fake1.json.kdfSaltB64).toBe(fake2.json.kdfSaltB64); // deterministic fake, no enumeration signal
  });

  test("new device requires approval from existing device", async () => {
    const app = setup();
    const reg = await req(app, "/auth/register", "POST", registerBody());
    const blocked = await req(app, "/auth/login", "POST", { email: "user@example.com", authVerifierB64: VERIFIER, device: deviceB });
    expect(blocked.status).toBe(403);
    expect(blocked.json.error.code).toBe("DEVICE_APPROVAL_REQUIRED");

    const statusBefore = await req(app, `/auth/device-status?deviceId=${deviceB.id}`, "GET");
    expect(statusBefore.json.status).toBe("pending");

    const approve = await req(app, `/devices/${deviceB.id}/approve`, "POST", {}, reg.json.accessToken);
    expect(approve.status).toBe(200);

    const login = await req(app, "/auth/login", "POST", { email: "user@example.com", authVerifierB64: VERIFIER, device: deviceB });
    expect(login.status).toBe(200);
  });

  test("refresh rotation + reuse revokes device sessions", async () => {
    const app = setup();
    const reg = await req(app, "/auth/register", "POST", registerBody());
    const refreshed = await req(app, "/auth/refresh", "POST", { refreshToken: reg.json.refreshToken });
    expect(refreshed.status).toBe(200);
    // Reusing the OLD refresh token must nuke the device's sessions
    const reuse = await req(app, "/auth/refresh", "POST", { refreshToken: reg.json.refreshToken });
    expect(reuse.status).toBe(401);
    const vault = await req(app, "/vault", "GET", undefined, refreshed.json.accessToken);
    expect(vault.status).toBe(401);
  });
});

describe("ciphertext sync", () => {
  test("push/pull, revision conflict, tombstone", async () => {
    const app = setup();
    const reg = await req(app, "/auth/register", "POST", registerBody());
    const token = reg.json.accessToken;
    const itemId = crypto.randomUUID();
    const item = { id: itemId, type: "login" as const, ciphertextB64: "Y2lwaGVy", wrappedItemKeyB64: "a2V5", revision: 1 };

    const put = await req(app, `/items/${itemId}`, "PUT", item, token);
    expect(put.status).toBe(200);

    const stale = await req(app, `/items/${itemId}`, "PUT", { ...item, ciphertextB64: "b2xk" }, token);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe("REVISION_CONFLICT");

    const update = await req(app, `/items/${itemId}`, "PUT", { ...item, revision: 2, ciphertextB64: "bmV3" }, token);
    expect(update.status).toBe(200);

    const pull = await req(app, "/items", "GET", undefined, token);
    expect(pull.json.items).toHaveLength(1);
    expect(pull.json.items[0].ciphertextB64).toBe("bmV3");

    const unauth = await req(app, "/items", "GET");
    expect(unauth.status).toBe(401);

    const del = await req(app, `/items/${itemId}`, "DELETE", undefined, token);
    expect(del.status).toBe(200);
    const after = await req(app, "/items", "GET", undefined, token);
    expect(after.json.items[0].deleted).toBe(true);
  });
});
