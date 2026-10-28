import { Hono, type Context, type Next } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { cors } from "hono/cors";
import { ChangePasswordRequest, CipherItem, LoginRequest, PreloginRequest, RecoverRequest, RecoveryInfoRequest, RegisterRequest, SyncPushRequest } from "@openpass/shared";
import type { SessionRow, Store, UserRow } from "./store/types";

/** Authenticated principal attached to the context by requireAuth. */
export interface AuthContext {
  user: UserRow;
  session: SessionRow;
}
type AppEnv = { Variables: { auth: AuthContext } };
type AppContext = Context<AppEnv>;
import { MemoryBlobStore, type BlobStore } from "./store/blobs";
import { fakeSaltB64, hashVerifier, randomTokenB64, sha256Hex, verifyVerifier } from "./crypto";

export interface AppOptions {
  allowRegistration?: boolean;
  pbkdf2Iterations?: number;
  now?: () => number;
  blobs?: BlobStore;
  maxAttachmentBytes?: number;
  /** Shared cross-isolate limiter (Durable Objects in production). Falls back to per-isolate memory. */
  rateLimiter?: (key: string, limit: number, windowMs: number) => Promise<boolean>;
}

const ACCESS_TTL = 15 * 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_KDF = { memoryKib: 65536, iterations: 3, parallelism: 4 };

export function createApp(store: Store, opts: AppOptions = {}) {
  const app = new Hono<AppEnv>();
  const now = opts.now ?? (() => Date.now());
  const attempts = new Map<string, { count: number; resetAt: number }>();

  app.use("*", cors({ origin: "*", allowHeaders: ["Authorization", "Content-Type"], allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Cache-Control", "no-store");
  });

  const rateLimited = async (key: string, limit = 20, windowMs = 60_000): Promise<boolean> => {
    if (opts.rateLimiter) return opts.rateLimiter(key, limit, windowMs);
    const t = now();
    const e = attempts.get(key);
    if (!e || t > e.resetAt) { attempts.set(key, { count: 1, resetAt: t + windowMs }); return false; }
    e.count += 1;
    return e.count > limit;
  };
  const err = (c: AppContext, status: ContentfulStatusCode, code: string, extra: object = {}) =>
    c.json({ error: { code, ...extra } }, status);

  async function issueSession(userId: string, deviceId: string) {
    const accessToken = randomTokenB64();
    const refreshToken = randomTokenB64();
    const session = {
      id: crypto.randomUUID(), userId, deviceId,
      accessHash: await sha256Hex(accessToken), refreshHash: await sha256Hex(refreshToken), prevRefreshHash: null,
      accessExpiresAt: now() + ACCESS_TTL, refreshExpiresAt: now() + REFRESH_TTL, revoked: 0, createdAt: new Date(now()).toISOString(),
    };
    await store.createSession(session);
    return { accessToken, refreshToken, sessionId: session.id };
  }

  async function authUser(c: AppContext): Promise<AuthContext | null> {
    const header = c.req.header("Authorization") ?? "";
    if (!header.startsWith("Bearer ")) return null;
    const session = await store.getSessionByAccessHash(await sha256Hex(header.slice(7)));
    if (!session || session.revoked || session.accessExpiresAt < now()) return null;
    const user = await store.getUserById(session.userId);
    return user ? { user, session } : null;
  }
  const requireAuth = async (c: AppContext, next: Next) => {
    const a = await authUser(c);
    if (!a) return err(c, 401, "UNAUTHORIZED");
    c.set("auth", a);
    await next();
  };

  app.get("/health", (c) => c.json({ ok: true, service: "openpass-api", version: 1 }));

  app.post("/auth/prelogin", async (c) => {
    const body = PreloginRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const email = body.data.email.toLowerCase();
    const user = await store.getUserByEmail(email);
    if (!user) return c.json({ kdfSaltB64: await fakeSaltB64(email), kdfParams: DEFAULT_KDF });
    return c.json({ kdfSaltB64: user.kdfSaltB64, kdfParams: JSON.parse(user.kdfParamsJson) });
  });

  app.post("/auth/register", async (c) => {
    if (opts.allowRegistration === false) return err(c, 403, "REGISTRATION_CLOSED");
    if (await rateLimited(`register:${c.req.header("CF-Connecting-IP") ?? "local"}`)) return err(c, 429, "RATE_LIMITED");
    const body = RegisterRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION", { issues: body.error.issues });
    const d = body.data;
    const email = d.email.toLowerCase();
    if (await store.getUserByEmail(email)) return err(c, 409, "EMAIL_TAKEN");
    const userId = crypto.randomUUID();
    const vaultId = crypto.randomUUID();
    const ts = new Date(now()).toISOString();
    await store.createUser({
      id: userId, email, verifierHash: await hashVerifier(d.authVerifierB64, opts.pbkdf2Iterations),
      kdfSaltB64: d.kdfSaltB64, kdfParamsJson: JSON.stringify(d.kdfParams),
      wrappedVaultKeyB64: d.wrappedVaultKeyB64, recoveryWrappedVaultKeyB64: d.recoveryWrappedVaultKeyB64,
      identityPublicKeyB64: d.identityPublicKeyB64, wrappedIdentityPrivateKeyB64: d.wrappedIdentityPrivateKeyB64,
      recoveryVerifierHash: await hashVerifier(d.recoveryAuthProofB64, opts.pbkdf2Iterations),
      vaultId, createdAt: ts,
    });
    // Bootstrap device is auto-approved.
    await store.upsertDevice({ userId, deviceId: d.device.id, name: d.device.name, platform: d.device.platform, status: "approved", createdAt: ts, lastSeenAt: ts });
    await store.audit(userId, "register", d.device.platform);
    const tokens = await issueSession(userId, d.device.id);
    return c.json({ userId, vaultId, ...tokens }, 201);
  });

  app.post("/auth/login", async (c) => {
    const ip = c.req.header("CF-Connecting-IP") ?? "local";
    if ((await rateLimited(`login:${ip}`)) || (await rateLimited(`login-ip:${ip}`, 100))) return err(c, 429, "RATE_LIMITED");
    const body = LoginRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const d = body.data;
    const user = await store.getUserByEmail(d.email.toLowerCase());
    // Always run a verification-shaped failure for unknown users.
    if (!user || !(await verifyVerifier(d.authVerifierB64, user.verifierHash))) return err(c, 401, "INVALID_CREDENTIALS");
    const ts = new Date(now()).toISOString();
    const existing = await store.getDevice(user.id, d.device.id);
    if (existing?.status !== "approved") {
      await store.upsertDevice({ userId: user.id, deviceId: d.device.id, name: d.device.name, platform: d.device.platform, status: "pending", createdAt: existing?.createdAt ?? ts, lastSeenAt: ts });
      await store.audit(user.id, "device_pending", d.device.id);
      return err(c, 403, "DEVICE_APPROVAL_REQUIRED", { deviceId: d.device.id });
    }
    await store.upsertDevice({ ...existing, name: d.device.name, lastSeenAt: ts });
    await store.audit(user.id, "login", d.device.id);
    const tokens = await issueSession(user.id, d.device.id);
    return c.json({
      userId: user.id, vaultId: user.vaultId,
      wrappedVaultKeyB64: user.wrappedVaultKeyB64, recoveryWrappedVaultKeyB64: user.recoveryWrappedVaultKeyB64,
      identityPublicKeyB64: user.identityPublicKeyB64, wrappedIdentityPrivateKeyB64: user.wrappedIdentityPrivateKeyB64,
      ...tokens,
    });
  });

  app.get("/auth/device-status", async (c) => {
    const deviceId = c.req.query("deviceId");
    if (!deviceId) return err(c, 400, "VALIDATION");
    return c.json({ status: await store.getDeviceStatus(deviceId) });
  });

  app.post("/auth/refresh", async (c) => {
    const body = (await c.req.json().catch(() => null)) as { refreshToken?: string } | null;
    if (!body?.refreshToken) return err(c, 400, "VALIDATION");
    const hash = await sha256Hex(body.refreshToken);
    const session = await store.getSessionByRefreshHash(hash);
    if (!session) {
      // Reuse of a rotated token = possible theft: revoke that device entirely.
      const prev = await store.getSessionByPrevRefreshHash(hash);
      if (prev) { await store.revokeDeviceSessions(prev.userId, prev.deviceId); await store.audit(prev.userId, "refresh_reuse_detected", prev.deviceId); }
      return err(c, 401, "UNAUTHORIZED");
    }
    if (session.revoked || session.refreshExpiresAt < now()) return err(c, 401, "UNAUTHORIZED");
    const accessToken = randomTokenB64();
    const refreshToken = randomTokenB64();
    await store.updateSessionTokens(session.id, await sha256Hex(accessToken), await sha256Hex(refreshToken), session.refreshHash, now() + ACCESS_TTL, now() + REFRESH_TTL);
    return c.json({ accessToken, refreshToken, sessionId: session.id });
  });

  app.post("/auth/change-password", requireAuth, async (c) => {
    const { user, session } = c.get("auth");
    const body = ChangePasswordRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const d = body.data;
    if (!(await verifyVerifier(d.currentAuthVerifierB64, user.verifierHash))) return err(c, 401, "INVALID_CREDENTIALS");
    await store.updateUserVerifier(user.id, await hashVerifier(d.newAuthVerifierB64, opts.pbkdf2Iterations),
      d.wrappedVaultKeyB64, user.recoveryWrappedVaultKeyB64, d.kdfSaltB64, JSON.stringify(d.kdfParams));
    await store.revokeOtherSessions(user.id, session.id);
    await store.audit(user.id, "password_changed", session.deviceId);
    return c.json({ ok: true });
  });

  // Recovery step 1: prove recovery-key possession, receive the recovery-wrapped vault key.
  app.post("/auth/recovery-info", async (c) => {
    if (await rateLimited(`recovery:${c.req.header("CF-Connecting-IP") ?? "local"}`, 10)) return err(c, 429, "RATE_LIMITED");
    const body = RecoveryInfoRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const user = await store.getUserByEmail(body.data.email.toLowerCase());
    if (!user || !user.recoveryVerifierHash || !(await verifyVerifier(body.data.recoveryAuthProofB64, user.recoveryVerifierHash))) {
      return err(c, 401, "INVALID_CREDENTIALS");
    }
    return c.json({ recoveryWrappedVaultKeyB64: user.recoveryWrappedVaultKeyB64, vaultId: user.vaultId });
  });

  // Recovery step 2: same proof authorizes replacing the auth verifier + wrapped keys.
  // The recovery key itself does not change, so its verifier hash and wrap remain valid.
  app.post("/auth/recover", async (c) => {
    if (await rateLimited(`recover:${c.req.header("CF-Connecting-IP") ?? "local"}`, 10)) return err(c, 429, "RATE_LIMITED");
    const body = RecoverRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const d = body.data;
    const user = await store.getUserByEmail(d.email.toLowerCase());
    if (!user || !user.recoveryVerifierHash || !(await verifyVerifier(d.recoveryAuthProofB64, user.recoveryVerifierHash))) {
      return err(c, 401, "INVALID_CREDENTIALS");
    }
    await store.updateUserVerifier(user.id, await hashVerifier(d.newAuthVerifierB64, opts.pbkdf2Iterations),
      d.wrappedVaultKeyB64, d.recoveryWrappedVaultKeyB64, d.kdfSaltB64, JSON.stringify(d.kdfParams));
    await store.revokeOtherSessions(user.id, null); // all sessions revoked; user logs in fresh
    await store.audit(user.id, "account_recovered", "");
    return c.json({ ok: true });
  });

  app.post("/auth/logout", requireAuth, async (c) => {
    const { session } = c.get("auth");
    await store.revokeSession(session.id);
    return c.json({ ok: true });
  });

  app.get("/vault", requireAuth, async (c) => {
    const { user } = c.get("auth");
    return c.json({
      vaultId: user.vaultId, wrappedVaultKeyB64: user.wrappedVaultKeyB64,
      recoveryWrappedVaultKeyB64: user.recoveryWrappedVaultKeyB64,
      kdfSaltB64: user.kdfSaltB64, kdfParams: JSON.parse(user.kdfParamsJson),
    });
  });

  app.get("/devices", requireAuth, async (c) => {
    const { user, session } = c.get("auth");
    const devices = await store.listDevices(user.id);
    return c.json({ devices: devices.map((d) => ({ ...d, current: d.deviceId === session.deviceId })) });
  });

  app.get("/devices/pending", requireAuth, async (c) => {
    const { user } = c.get("auth");
    return c.json({ devices: await store.listPendingDevices(user.id) });
  });

  app.post("/devices/:deviceId/approve", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const deviceId = param(c, "deviceId");
    if (!(await store.getDevice(user.id, deviceId))) return err(c, 404, "NOT_FOUND");
    await store.setDeviceStatus(user.id, deviceId, "approved");
    await store.audit(user.id, "device_approved", deviceId);
    return c.json({ ok: true });
  });

  app.delete("/devices/:deviceId", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const deviceId = param(c, "deviceId");
    await store.revokeDeviceSessions(user.id, deviceId);
    await store.deleteDevice(user.id, deviceId);
    await store.audit(user.id, "device_revoked", deviceId);
    return c.json({ ok: true });
  });

  const param = (c: AppContext, name: string): string => c.req.param(name) ?? "";

  const publicItem = (i: Awaited<ReturnType<Store["listItemsSince"]>>[number]) => ({
    id: i.id, type: i.type, ciphertextB64: i.ciphertextB64, wrappedItemKeyB64: i.wrappedItemKeyB64,
    revision: i.revision, deleted: i.deleted === 1, updatedAt: i.updatedAt,
  });

  async function upsertChecked(user: { id: string; vaultId: string }, item: CipherItem & { deleted?: boolean }) {
    const existing = await store.getItem(user.vaultId, item.id);
    const expected = existing ? existing.revision + 1 : 1;
    if (item.revision !== expected) return { conflict: existing };
    if (existing) await store.addHistory(existing, new Date(now()).toISOString());
    const row = {
      id: item.id, vaultId: user.vaultId, userId: user.id, type: item.type,
      ciphertextB64: item.ciphertextB64, wrappedItemKeyB64: item.wrappedItemKeyB64,
      revision: item.revision, deleted: item.deleted ? 1 : 0, updatedAt: new Date(now()).toISOString(),
    };
    await store.upsertItem(row);
    return { item: row };
  }

  app.get("/items", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const items = await store.listItemsSince(user.vaultId, c.req.query("since") ?? null);
    return c.json({ items: items.map(publicItem), cursor: items.length ? items[items.length - 1].updatedAt : (c.req.query("since") ?? null) });
  });

  app.put("/items/:id", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const body = CipherItem.safeParse({ ...((await c.req.json().catch(() => null)) ?? {}), id: param(c, "id") });
    if (!body.success) return err(c, 400, "VALIDATION");
    const r = await upsertChecked(user, body.data);
    if (r.conflict) return err(c, 409, "REVISION_CONFLICT", { serverItem: r.conflict ? publicItem(r.conflict) : null });
    return c.json({ item: publicItem(r.item!) });
  });

  app.post("/sync/push", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const body = SyncPushRequest.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return err(c, 400, "VALIDATION");
    const results = [];
    for (const item of body.data.items) {
      const r = await upsertChecked(user, item);
      results.push(r.conflict ? { id: item.id, status: "conflict", serverItem: publicItem(r.conflict) } : { id: item.id, status: "ok", revision: item.revision });
    }
    return c.json({ results });
  });

  app.delete("/items/:id", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const existing = await store.getItem(user.vaultId, param(c, "id"));
    if (!existing) return err(c, 404, "NOT_FOUND");
    await store.addHistory(existing, new Date(now()).toISOString());
    await store.upsertItem({ ...existing, deleted: 1, revision: existing.revision + 1, updatedAt: new Date(now()).toISOString() });
    return c.json({ ok: true, revision: existing.revision + 1 });
  });

  app.get("/items/:id/history", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const history = await store.listHistory(user.vaultId, param(c, "id"));
    return c.json({
      history: history.map((h) => ({
        revision: h.revision, ciphertextB64: h.ciphertextB64, wrappedItemKeyB64: h.wrappedItemKeyB64,
        deleted: h.deleted === 1, updatedAt: h.updatedAt,
      })),
    });
  });

  // Encrypted file blobs. Body is chunked-AEAD ciphertext produced by the Rust core;
  // the server cannot inspect content. Metadata in D1, bytes in R2 (or memory in tests).
  const blobs: BlobStore = opts.blobs ?? new MemoryBlobStore();
  const maxBytes = opts.maxAttachmentBytes ?? 25 * 1024 * 1024;

  app.post("/attachments", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    if (bytes.length === 0) return err(c, 400, "VALIDATION");
    if (bytes.length > maxBytes) return err(c, 413, "VALIDATION", { message: `attachment exceeds ${maxBytes} bytes` });
    const id = crypto.randomUUID();
    await blobs.put(`${user.id}/${id}`, bytes);
    await store.createAttachment({ id, userId: user.id, vaultId: user.vaultId, sizeBytes: bytes.length, createdAt: new Date(now()).toISOString() });
    await store.audit(user.id, "attachment_uploaded", id);
    return c.json({ id, sizeBytes: bytes.length }, 201);
  });

  app.get("/attachments/:id", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const meta = await store.getAttachment(user.id, param(c, "id"));
    if (!meta) return err(c, 404, "NOT_FOUND");
    const bytes = await blobs.get(`${user.id}/${meta.id}`);
    if (!bytes) return err(c, 404, "NOT_FOUND");
    return new Response(bytes as BodyInit, {
      headers: { "Content-Type": "application/octet-stream", "Content-Length": String(bytes.length), "Cache-Control": "no-store" },
    });
  });

  app.delete("/attachments/:id", requireAuth, async (c) => {
    const { user } = c.get("auth");
    const meta = await store.getAttachment(user.id, param(c, "id"));
    if (!meta) return err(c, 404, "NOT_FOUND");
    await blobs.delete(`${user.id}/${meta.id}`);
    await store.deleteAttachment(user.id, meta.id);
    await store.audit(user.id, "attachment_deleted", meta.id);
    return c.json({ ok: true });
  });

  return app;
}
