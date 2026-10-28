import { z } from "zod";

/** Plaintext item schemas — these exist ONLY on clients, inside encryption. Never sent to the server decrypted. */

export const ItemType = z.enum(["login", "card", "identity", "secure_note", "totp", "passkey", "file"]);
export type ItemType = z.infer<typeof ItemType>;

const base = {
  v: z.literal(1),
  name: z.string().min(1).max(200),
  notes: z.string().max(10_000).optional(),
  favorite: z.boolean().default(false),
  folderId: z.string().uuid().nullable().default(null),
  tags: z.array(z.string().max(50)).default([]),
};

export const LoginItem = z.object({
  ...base, type: z.literal("login"),
  username: z.string().max(500).default(""),
  password: z.string().max(4096).default(""),
  uris: z.array(z.object({ uri: z.string().max(2048), match: z.enum(["domain", "host", "startsWith", "exact", "never"]).default("domain") })).default([]),
  totpId: z.string().uuid().nullable().default(null),
  customFields: z.array(z.object({ name: z.string(), value: z.string(), hidden: z.boolean().default(false) })).default([]),
});

export const CardItem = z.object({
  ...base, type: z.literal("card"),
  cardholder: z.string().max(200).default(""),
  number: z.string().max(32).default(""),
  brand: z.string().max(50).default(""),
  expMonth: z.string().max(2).default(""),
  expYear: z.string().max(4).default(""),
  cvv: z.string().max(8).default(""),
});

export const IdentityItem = z.object({
  ...base, type: z.literal("identity"),
  firstName: z.string().max(200).default(""), lastName: z.string().max(200).default(""),
  email: z.string().max(500).default(""), phone: z.string().max(50).default(""),
  address1: z.string().max(500).default(""), address2: z.string().max(500).default(""),
  city: z.string().max(200).default(""), state: z.string().max(200).default(""),
  postcode: z.string().max(50).default(""), country: z.string().max(100).default(""),
});

export const SecureNoteItem = z.object({ ...base, type: z.literal("secure_note"), content: z.string().max(100_000).default("") });

export const TotpItem = z.object({
  ...base, type: z.literal("totp"),
  issuer: z.string().max(200).default(""), account: z.string().max(500).default(""),
  secretBase32: z.string().max(512),
  algorithm: z.enum(["SHA1", "SHA256", "SHA512"]).default("SHA1"),
  digits: z.union([z.literal(6), z.literal(7), z.literal(8)]).default(6),
  period: z.number().int().min(5).max(300).default(30),
});

export const PasskeyItem = z.object({
  ...base, type: z.literal("passkey"),
  rpId: z.string().max(253), rpName: z.string().max(200).default(""),
  userName: z.string().max(500).default(""), credentialIdB64: z.string(),
  privateKeyPkcs8B64: z.string(), // encrypted as part of item plaintext; never leaves vault plaintext context
  counter: z.number().int().min(0).default(0),
});

export const FileItem = z.object({
  ...base, type: z.literal("file"),
  fileName: z.string().max(500), mimeType: z.string().max(200).default("application/octet-stream"),
  sizeBytes: z.number().int().min(0), attachmentId: z.string().uuid(),
  wrappedFileKeyB64: z.string(),
});

export const VaultItemPlaintext = z.discriminatedUnion("type", [LoginItem, CardItem, IdentityItem, SecureNoteItem, TotpItem, PasskeyItem, FileItem]);
export type VaultItemPlaintext = z.infer<typeof VaultItemPlaintext>;
