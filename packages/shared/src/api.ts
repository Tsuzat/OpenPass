import { z } from "zod";
import { ItemType } from "./items";

export const KdfParamsSchema = z.object({
  memoryKib: z.number().int().positive(),
  iterations: z.number().int().positive(),
  parallelism: z.number().int().positive(),
  saltB64: z.string(),
});

export const DeviceInfo = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100),
  platform: z.enum(["macos", "android", "web", "extension", "ios", "windows", "linux"]),
});

export const RegisterRequest = z.object({
  email: z.string().email().max(320),
  authVerifierB64: z.string().min(40).max(64), // 32 bytes, base64
  kdfSaltB64: z.string(),
  kdfParams: KdfParamsSchema.omit({ saltB64: true }),
  wrappedVaultKeyB64: z.string(),
  recoveryWrappedVaultKeyB64: z.string(),
  recoveryAuthProofB64: z.string().min(40).max(64), // HKDF(recoveryKey, "openpass/recovery-auth/v1"), 32 bytes
  identityPublicKeyB64: z.string(),
  wrappedIdentityPrivateKeyB64: z.string(),
  device: DeviceInfo,
});

export const PreloginRequest = z.object({ email: z.string().email().max(320) });
export const LoginRequest = z.object({
  email: z.string().email().max(320),
  authVerifierB64: z.string().min(40).max(64),
  device: DeviceInfo,
});

/** Ciphertext item as the server sees it. Plaintext schema is never applied server-side. */
export const CipherItem = z.object({
  id: z.string().uuid(),
  type: ItemType,
  ciphertextB64: z.string().min(1).max(2_000_000),
  wrappedItemKeyB64: z.string().min(1).max(1024),
  revision: z.number().int().min(1),
});
export type CipherItem = z.infer<typeof CipherItem>;

export const ChangePasswordRequest = z.object({
  currentAuthVerifierB64: z.string().min(40).max(64),
  newAuthVerifierB64: z.string().min(40).max(64),
  kdfSaltB64: z.string(),
  kdfParams: KdfParamsSchema.omit({ saltB64: true }),
  wrappedVaultKeyB64: z.string(),
});

export const RecoveryInfoRequest = z.object({
  email: z.string().email().max(320),
  recoveryAuthProofB64: z.string().min(40).max(64),
});

export const RecoverRequest = RecoveryInfoRequest.extend({
  newAuthVerifierB64: z.string().min(40).max(64),
  kdfSaltB64: z.string(),
  kdfParams: KdfParamsSchema.omit({ saltB64: true }),
  wrappedVaultKeyB64: z.string(),
  recoveryWrappedVaultKeyB64: z.string(),
});

export const SyncPushRequest = z.object({ items: z.array(CipherItem).max(500) });
export type ApiErrorCode =
  | "VALIDATION" | "EMAIL_TAKEN" | "INVALID_CREDENTIALS" | "DEVICE_APPROVAL_REQUIRED"
  | "UNAUTHORIZED" | "REVISION_CONFLICT" | "REGISTRATION_CLOSED" | "RATE_LIMITED" | "NOT_FOUND";
