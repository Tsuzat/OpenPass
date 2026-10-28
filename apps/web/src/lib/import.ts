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
  const totpI = col("totp", "login_totp", "one-time password");
  if (userI < 0 && passI < 0) throw new Error("CSV missing username/password columns");

  const out: ImportedItem[] = [];
  for (const line of lines.slice(1)) {
    const cells = splitCsvLine(line);
    const get = (i: number) => (i >= 0 ? (cells[i] ?? "").trim() : "");
    const name = get(nameI) || get(urlI) || get(userI) || "Imported login";
    out.push({
      ...base(name), type: "login", username: get(userI), password: get(passI),
      uris: get(urlI) ? [{ uri: get(urlI), match: "domain" as const }] : [],
      notes: get(notesI), totpId: null, customFields: [],
    });
    const totp = get(totpI) ? normalizeTotp(get(totpI)) : null;
    if (totp) out.push({ ...base(`${name} (TOTP)`), type: "totp", issuer: totp.issuer, account: totp.account || get(userI), secretBase32: totp.secretBase32, algorithm: "SHA1", digits: 6, period: 30 });
  }
  return out;
}

export function parseImportFile(filename: string, text: string): ImportedItem[] {
  if (filename.toLowerCase().endsWith(".csv")) return parseGenericCsv(text);
  try {
    const parsed = JSON.parse(text) as { format?: string };
    if (parsed.format === "openpass-export") throw new Error("Encrypted OpenPass export — use the decrypt-import flow with its export password");
  } catch (e) { if (e instanceof Error && e.message.includes("OpenPass")) throw e; }
  return parseBitwardenJson(text);
}
