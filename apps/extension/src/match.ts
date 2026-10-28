/** URI matching for autofill (mirrors the item schema in @openpass/shared). Pure and unit-tested. */

export type MatchType = "domain" | "host" | "startsWith" | "exact" | "never";

// Minimal multi-label public suffix handling for common cases.
const MULTI_LABEL_SUFFIXES = new Set(["co.uk", "org.uk", "com.au", "net.au", "co.jp", "com.br", "co.in"]);

export function registrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function hostOf(uri: string): string | null {
  try { return new URL(uri.includes("://") ? uri : `https://${uri}`).hostname.toLowerCase(); }
  catch { return null; }
}

/**
 * Should a credential saved for `savedUri` be offered on `pageHost`?
 * - never: never fill
 * - exact: full URI string equality handled by caller for host-level checks -> host equality
 * - host: exact host equality (subdomains do NOT match)
 * - domain: same registrable domain (subdomains match)
 */
export function uriMatches(savedUri: string, match: MatchType, pageHost: string): boolean {
  if (match === "never") return false;
  const savedHost = hostOf(savedUri);
  if (!savedHost) return false;
  const page = pageHost.toLowerCase();
  switch (match) {
    case "host": case "exact": return savedHost === page;
    case "startsWith": return page === savedHost || page.endsWith(`.${savedHost}`);
    case "domain": return registrableDomain(savedHost) === registrableDomain(page);
  }
}
