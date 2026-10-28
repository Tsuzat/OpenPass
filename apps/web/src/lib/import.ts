/** Import parsers producing OpenPass plaintext items (see @openpass/shared schemas). Pure + unit-tested. */

export type ImportedItem = Record<string, unknown> & { type: string; name: string };

const base = (name: string) => ({ v: 1, name: name || "(unnamed)", notes: "", favorite: false, folderId: null, tags: [] });

interface BitwardenItem {
  name?: string; notes?: string | null; favorite?: boolean;
  type: number; // 1 login, 2 secure note, 3 card, 4 identity
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: { uri?: string; match?: number | null }[] };
  card?: { cardholderName?: string | null; number?: string | null; brand?: string | null; expMonth?: string | null; expYear?: string | null; code?: string | null };
  identity?: { firstName?: string | null; lastName?: string | null; email?: string | null; phone?: string | null; address1?: string | null; city?: string | null; state?: string | null; postalCode?: string | null; country?: string | null };
  fields?: { name?: string; value?: string | null; type?: number }[];
}

const s = (v: string | null | undefined) => v ?? "";

/** Normalize a Bitwarden TOTP field: may be a raw secret or an otpauth:// URI. */
export function normalizeTotp(raw: string): { secretBase32: string; issuer: string; account: string } | null {
  const value = raw.trim();
  if (!value) return null;
  if (/^[A-Za-z2-7=\s]+$/.test(value) && value.replace(/[\s=]/g, "").length >= 8) {
    return { secretBase32: value.replace(/\s/g, "").toUpperCase(), issuer: "", account: "" };
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "otpauth:") return null;
    const secret = url.searchParams.get("secret");
    if (!secret) return null;
    const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
    const [issuerFromLabel, account] = label.includes(":") ? label.split(/:(.+)/).filter(Boolean) : ["", label];
    return {
      secretBase32: secret.toUpperCase(),
      issuer: url.searchParams.get("issuer") ?? issuerFromLabel ?? "",
      account: (account ?? "").trim(),
    };
  } catch { return null; }
}

export function parseBitwardenJson(text: string): ImportedItem[] {
  const data = JSON.parse(text) as { items?: BitwardenItem[] };
  if (!Array.isArray(data.items)) throw new Error("Not a Bitwarden export (missing items)");
  const out: ImportedItem[] = [];
  for (const item of data.items) {
    const common = { ...base(s(item.name)), notes: s(item.notes), favorite: !!item.favorite };
    if (item.type === 1 && item.login) {
      const login: ImportedItem = {
        ...common, type: "login", username: s(item.login.username), password: s(item.login.password),
        uris: (item.login.uris ?? []).filter((u) => u.uri).map((u) => ({ uri: u.uri!, match: "domain" as const })),
        totpId: null,
        customFields: (item.fields ?? []).map((f) => ({ name: s(f.name), value: s(f.value), hidden: f.type === 1 })),
      };
      out.push(login);
      const totp = item.login.totp ? normalizeTotp(item.login.totp) : null;
      if (totp) out.push({ ...common, type: "totp", name: `${s(item.name)} (TOTP)`, issuer: totp.issuer, account: totp.account || s(item.login.username), secretBase32: totp.secretBase32, algorithm: "SHA1", digits: 6, period: 30 });
    } else if (item.type === 2) {
      out.push({ ...common, type: "secure_note", content: s(item.notes) });
    } else if (item.type === 3 && item.card) {
      out.push({ ...common, type: "card", cardholder: s(item.card.cardholderName), number: s(item.card.number), brand: s(item.card.brand), expMonth: s(item.card.expMonth), expYear: s(item.card.expYear), cvv: s(item.card.code) });
    } else if (item.type === 4 && item.identity) {
      out.push({
        ...common, type: "identity", firstName: s(item.identity.firstName), lastName: s(item.identity.lastName),
        email: s(item.identity.email), phone: s(item.identity.phone), address1: s(item.identity.address1),
        address2: "", city: s(item.identity.city), state: s(item.identity.state), postcode: s(item.identity.postalCode), country: s(item.identity.country),
      });
    }
  }
  return out;
}

/** Split one CSV line honoring quotes. */
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = ""; let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * Generic CSV import. Recognizes common headers across Chrome / Bitwarden /
 * LastPass exports: name/title, url/uri/website, username/login, password, notes, totp.
 */
export function parseGenericCsv(text: string): ImportedItem[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) throw new Error("CSV has no data rows");
  const header = splitCsvLine(lines[0]).map((h) => h.trim().toLowerCase());
  const col = (...names: string[]) => header.findIndex((h) => names.includes(h));
  const nameI = col("name", "title");
  const urlI = col("url", "uri", "website", "login_uri", "web site");
  const userI = col("username", "login", "login_username", "user", "email");
  const passI = col("password", "login_password");
  const notesI = col("notes", "note", "comments");
  const totpI = col("totp", "login_totp", "one-time password", "otpauth", "totp seed", "otp");
  const groupI = col("group", "folder", "category", "vault", "chamber");
  if (userI < 0 && passI < 0) throw new Error("CSV missing username/password columns");

  const out: ImportedItem[] = [];
  for (const line of lines.slice(1)) {
    const cells = splitCsvLine(line);
    const get = (i: number) => (i >= 0 ? (cells[i] ?? "").trim() : "");
    const name = get(nameI) || get(urlI) || get(userI) || "Imported login";
    const group = get(groupI);
    out.push({
      ...base(name), type: "login", username: get(userI), password: get(passI),
      uris: get(urlI) ? [{ uri: get(urlI), match: "domain" as const }] : [],
      notes: get(notesI), totpId: null, customFields: [],
      ...(group ? { tags: [group] } : {}),
    });
    const totp = get(totpI) ? normalizeTotp(get(totpI)) : null;
    if (totp) out.push({ ...base(`${name} (TOTP)`), type: "totp", issuer: totp.issuer, account: totp.account || get(userI), secretBase32: totp.secretBase32, algorithm: "SHA1", digits: 6, period: 30 });
  }
  return out;
}

// ---------- 1Password (.1pux export.data + CSV) ----------

function fieldValue(v: unknown): string {
  if (typeof v === "string") return v;
  if (v && typeof v === "object") {
    for (const val of Object.values(v as Record<string, unknown>)) if (typeof val === "string" && val) return val;
  }
  return "";
}

interface OnePuxItem {
  categoryUuid?: string; fav?: boolean;
  overview?: { title?: string; url?: string; urls?: { url?: string }[]; tags?: string[] };
  details?: {
    notesPlain?: string;
    loginFields?: { value?: unknown; designation?: string; name?: string }[];
    sections?: { title?: string; fields?: { title?: string; value?: unknown }[] }[];
  };
}

/** Parse the export.data JSON inside a .1pux archive (or the parsed object itself). */
export function parse1PasswordData(data: unknown): ImportedItem[] {
  const root = data as { accounts?: { vaults?: { attrs?: { name?: string }; items?: OnePuxItem[] }[] }[] };
  if (!Array.isArray(root.accounts)) throw new Error("Not a 1Password export (missing accounts)");
  const out: ImportedItem[] = [];
  for (const account of root.accounts) {
    for (const vault of account.vaults ?? []) {
      const vaultName = vault.attrs?.name ?? "";
      for (const item of vault.items ?? []) {
        const title = item.overview?.title ?? "(unnamed)";
        const tags = [...(item.overview?.tags ?? []), ...(vaultName ? [vaultName] : [])];
        const common = { ...base(title), notes: item.details?.notesPlain ?? "", favorite: !!item.fav, tags };
        const sectionFields = (item.details?.sections ?? []).flatMap((sec) => sec.fields ?? []);
        const sectionValue = (...needles: string[]) =>
          fieldValue(sectionFields.find((f) => needles.some((n) => (f.title ?? "").toLowerCase().includes(n)))?.value);
        const loginField = (designation: string) =>
          fieldValue(item.details?.loginFields?.find((f) => f.designation === designation)?.value);
        const username = loginField("username") || sectionValue("username", "user name", "email");
        const password = loginField("password") || sectionValue("password");
        const urls = (item.overview?.urls ?? []).map((u) => u.url).filter((u): u is string => !!u);
        if (item.overview?.url && !urls.includes(item.overview.url)) urls.unshift(item.overview.url);
        const totpRaw = sectionValue("one-time password", "otp", "totp") ||
          fieldValue(item.details?.loginFields?.find((f) => (f.name ?? "").toLowerCase().includes("otp"))?.value);

        switch (item.categoryUuid) {
          case "002":
            out.push({ ...common, type: "card", cardholder: sectionValue("cardholder", "name on card"), number: sectionValue("card number", "number"), brand: sectionValue("type", "brand"), expMonth: sectionValue("expiry")?.slice(0, 2) ?? "", expYear: sectionValue("expiry")?.slice(-4) ?? "", cvv: sectionValue("cvv", "verification") });
            break;
          case "003":
            out.push({ ...common, type: "identity", firstName: sectionValue("first name", "given"), lastName: sectionValue("last name", "surname"), email: sectionValue("email"), phone: sectionValue("phone"), address1: sectionValue("address"), address2: "", city: sectionValue("city"), state: sectionValue("state", "province"), postcode: sectionValue("zip", "postal"), country: sectionValue("country") });
            break;
          case "005":
            out.push({ ...common, type: "secure_note", content: item.details?.notesPlain ?? "" });
            break;
          case "001": case "004": default: {
            if (username || password || urls.length) {
              out.push({ ...common, type: "login", username, password, uris: urls.map((uri) => ({ uri, match: "domain" as const })), totpId: null, customFields: sectionFields.filter((f) => f.title && fieldValue(f.value)).map((f) => ({ name: f.title!, value: fieldValue(f.value), hidden: false })) });
              const totp = totpRaw ? normalizeTotp(totpRaw) : null;
              if (totp) out.push({ ...common, type: "totp", name: `${title} (TOTP)`, issuer: totp.issuer, account: totp.account || username, secretBase32: totp.secretBase32, algorithm: "SHA1", digits: 6, period: 30 });
            } else {
              // Unsupported/empty categories fall back to a secure note, never dropped.
              out.push({ ...common, type: "secure_note", content: item.details?.notesPlain ?? JSON.stringify(item.details ?? {}, null, 2) });
            }
          }
        }
      }
    }
  }
  return out;
}

export async function parse1Password1pux(bytes: Uint8Array): Promise<ImportedItem[]> {
  const { unzipSync, strFromU8 } = await import("fflate");
  const files = unzipSync(bytes);
  const entry = Object.keys(files).find((k) => k.endsWith("export.data"));
  if (!entry) throw new Error("Invalid .1pux: export.data not found");
  return parse1PasswordData(JSON.parse(strFromU8(files[entry])));
}

// ---------- Zoho Vault (CSV + JSON) ----------

export function isZohoCsv(text: string): boolean {
  const first = (text.split(/\r?\n/)[0] ?? "").toLowerCase();
  return first.includes("password name") || first.includes("secret type") || first.includes("chamber");
}

export function parseZohoCsv(text: string): ImportedItem[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) throw new Error("Zoho CSV has no data rows");
  const header = splitCsvLine(lines[0]).map((h) => h.trim().toLowerCase());
  const col = (...names: string[]) => header.findIndex((h) => names.includes(h));
  const findLike = (needle: string) => header.findIndex((h) => h.includes(needle));
  const nameI = col("password name", "name", "password title", "title");
  const userI = col("user name", "username", "user id");
  const passI = col("password", "secret");
  const urlI = col("url", "web site", "website");
  const notesI = col("notes", "description", "notes/description");
  const typeI = col("secret type", "password type", "type");
  const chamberI = findLike("chamber");
  const cardNumI = findLike("card number");
  const expI = findLike("expiry");
  const cvvI = findLike("cvv");

  const out: ImportedItem[] = [];
  for (const line of lines.slice(1)) {
    const cells = splitCsvLine(line);
    const get = (i: number) => (i >= 0 ? (cells[i] ?? "").trim() : "");
    const name = get(nameI) || get(urlI) || "(unnamed)";
    const secretType = get(typeI).toLowerCase();
    const tags = get(chamberI) ? [get(chamberI)] : [];
    if (secretType.includes("card") || get(cardNumI)) {
      const exp = get(expI);
      out.push({ ...base(name), type: "card", cardholder: get(userI), number: get(cardNumI) || get(passI), brand: "", expMonth: exp.slice(0, 2), expYear: exp.slice(-4), cvv: get(cvvI), notes: get(notesI), tags });
    } else if (secretType.includes("note")) {
      out.push({ ...base(name), type: "secure_note", content: get(passI) || get(notesI), tags });
    } else {
      out.push({ ...base(name), type: "login", username: get(userI), password: get(passI), uris: get(urlI) ? [{ uri: get(urlI), match: "domain" as const }] : [], notes: get(notesI), totpId: null, customFields: [], tags });
    }
  }
  return out;
}

export function parseZohoJson(text: string): ImportedItem[] {
  const data = JSON.parse(text) as Record<string, unknown>;
  const arr = (data.passwords ?? data.secrets ?? data.data) as Record<string, unknown>[] | undefined;
  if (!Array.isArray(arr)) throw new Error("Not a Zoho Vault JSON export");
  const get = (obj: Record<string, unknown>, ...keys: string[]) => {
    for (const k of keys) if (typeof obj[k] === "string") return obj[k] as string;
    return "";
  };
  return arr.map((p) => {
    const name = get(p, "name", "password_name", "passwordName", "title") || "(unnamed)";
    const type = get(p, "secret_type", "secretType", "type").toLowerCase();
    return type.includes("note")
      ? { ...base(name), type: "secure_note", content: get(p, "password", "notes") }
      : { ...base(name), type: "login", username: get(p, "username", "user_name", "userName"), password: get(p, "password"), uris: get(p, "url") ? [{ uri: get(p, "url"), match: "domain" as const }] : [], notes: get(p, "notes", "description"), totpId: null, customFields: [] };
  });
}

// ---------- Proton Pass (JSON) ----------

export function parseProtonJson(text: string): ImportedItem[] {
  const data = JSON.parse(text) as { items?: { data?: { type?: string; metadata?: { name?: string; note?: string }; content?: { username?: string; password?: string; urls?: string[]; totpUri?: string; cardholderName?: string; number?: string; expMonth?: string; expYear?: string; verificationNumber?: string } } }[] };
  if (!Array.isArray(data.items)) throw new Error("Not a Proton Pass export");
  const out: ImportedItem[] = [];
  for (const item of data.items) {
    const d = item.data; if (!d) continue;
    const name = d.metadata?.name ?? "(unnamed)";
    const c = d.content ?? {};
    if (d.type === "creditCard") {
      out.push({ ...base(name), type: "card", cardholder: c.cardholderName ?? "", number: c.number ?? "", brand: "", expMonth: c.expMonth ?? "", expYear: c.expYear ?? "", cvv: c.verificationNumber ?? "", notes: d.metadata?.note ?? "" });
    } else if (d.type === "note") {
      out.push({ ...base(name), type: "secure_note", content: d.metadata?.note ?? "", notes: "" });
    } else {
      out.push({ ...base(name), type: "login", username: c.username ?? "", password: c.password ?? "", uris: (c.urls ?? []).map((uri) => ({ uri, match: "domain" as const })), notes: d.metadata?.note ?? "", totpId: null, customFields: [] });
      const totp = c.totpUri ? normalizeTotp(c.totpUri) : null;
      if (totp) out.push({ ...base(`${name} (TOTP)`), type: "totp", issuer: totp.issuer, account: totp.account || (c.username ?? ""), secretBase32: totp.secretBase32, algorithm: "SHA1", digits: 6, period: 30 });
    }
  }
  return out;
}

// ---------- Dedupe ----------

export function dedupeKey(item: { type?: unknown; name?: unknown; username?: unknown; uris?: unknown }): string {
  const firstUri = Array.isArray(item.uris) ? String((item.uris[0] as { uri?: string } | undefined)?.uri ?? "") : "";
  let host = firstUri;
  try { host = new URL(firstUri.includes("://") ? firstUri : `https://${firstUri}`).hostname; } catch { /* keep raw */ }
  return [String(item.type ?? ""), String(item.name ?? "").trim().toLowerCase(), String(item.username ?? "").trim().toLowerCase(), host.toLowerCase()].join("|");
}

export function partitionDuplicates<T extends Record<string, unknown>>(
  incoming: T[], existingKeys: Set<string>,
): { fresh: T[]; duplicates: T[] } {
  const seen = new Set(existingKeys);
  const fresh: T[] = []; const duplicates: T[] = [];
  for (const item of incoming) {
    const key = dedupeKey(item);
    if (seen.has(key)) duplicates.push(item);
    else { seen.add(key); fresh.push(item); }
  }
  return { fresh, duplicates };
}

// ---------- Detection / entry points ----------

export async function parseImportBytes(filename: string, bytes: Uint8Array): Promise<ImportedItem[]> {
  const isZip = bytes.length > 3 && bytes[0] === 0x50 && bytes[1] === 0x4b;
  if (isZip || filename.toLowerCase().endsWith(".1pux")) return parse1Password1pux(bytes);
  const text = new TextDecoder().decode(bytes);
  if (filename.toLowerCase().endsWith(".csv")) return isZohoCsv(text) ? parseZohoCsv(text) : parseGenericCsv(text);
  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (parsed.format === "openpass-export") throw new Error("Encrypted OpenPass export — use the decrypt-import flow with its export password");
  if (Array.isArray(parsed.accounts)) return parse1PasswordData(parsed);
  if (Array.isArray(parsed.items) && (parsed.items[0] as { data?: unknown })?.data) return parseProtonJson(text);
  if (Array.isArray(parsed.passwords) || Array.isArray(parsed.secrets)) return parseZohoJson(text);
  return parseBitwardenJson(text);
}

export function parseImportFile(filename: string, text: string): ImportedItem[] {
  if (filename.toLowerCase().endsWith(".csv")) return isZohoCsv(text) ? parseZohoCsv(text) : parseGenericCsv(text);
  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (parsed.format === "openpass-export") throw new Error("Encrypted OpenPass export — use the decrypt-import flow with its export password");
  if (Array.isArray(parsed.accounts)) return parse1PasswordData(parsed);
  if (Array.isArray(parsed.items) && (parsed.items[0] as { data?: unknown })?.data) return parseProtonJson(text);
  if (Array.isArray(parsed.passwords) || Array.isArray(parsed.secrets)) return parseZohoJson(text);
  return parseBitwardenJson(text);
}
