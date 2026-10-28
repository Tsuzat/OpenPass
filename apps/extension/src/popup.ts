/* eslint-disable @typescript-eslint/no-explicit-any */
declare const chrome: any;
import { derive, decryptItem, unwrapKey } from "./crypto";
import { uriMatches, type MatchType } from "./match";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const status = document.getElementById("status") as HTMLParagraphElement;

let accessToken: string | null = null;
let vaultKeyB64: string | null = null;

async function deviceId(): Promise<string> {
  const stored = await chrome.storage.local.get(["openpass.deviceId"]);
  if (stored["openpass.deviceId"]) return stored["openpass.deviceId"] as string;
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ "openpass.deviceId": id });
  return id;
}

async function api(server: string, path: string, method = "GET", body?: unknown, auth = false): Promise<any> {
  const res = await fetch(`${server}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(auth && accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as any)?.error?.code ?? `HTTP_${res.status}`);
  return data;
}

async function unlock() {
  const server = $("server").value.replace(/\/$/, "");
  const email = $("email").value;
  const password = $("password").value;
  status.textContent = "Deriving keys (Argon2id)…";
  try {
    await chrome.storage.local.set({ "openpass.serverUrl": server, "openpass.email": email });
    const pre = await api(server, "/auth/prelogin", "POST", { email });
    const auth = await derive(password, { ...pre.kdfParams, saltB64: pre.kdfSaltB64 });
    const login = await api(server, "/auth/login", "POST", {
      email, authVerifierB64: auth.authVerifierB64,
      device: { id: await deviceId(), name: "Browser Extension", platform: "extension" },
    });
    accessToken = login.accessToken;
    vaultKeyB64 = await unwrapKey(auth.kekB64, login.wrappedVaultKeyB64);
    $("password").value = "";
    (document.getElementById("locked") as HTMLDivElement).hidden = true;
    (document.getElementById("unlocked") as HTMLDivElement).hidden = false;
    await showMatches(server);
  } catch (e) {
    status.textContent = e instanceof Error && e.message === "DEVICE_APPROVAL_REQUIRED"
      ? "New device: approve this extension from an existing device, then unlock again."
      : `Unlock failed: ${e instanceof Error ? e.message : String(e)}`;
  }
}

async function showMatches(server: string) {
  const vaultStatus = document.getElementById("vault-status") as HTMLParagraphElement;
  const container = document.getElementById("items") as HTMLDivElement;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const host: string = tab?.url ? new URL(tab.url).hostname : "";
  vaultStatus.textContent = host ? `Credentials for ${host}` : "No active tab host.";
  container.innerHTML = "";
  if (!host || !accessToken || !vaultKeyB64) return;

  const data = await api(server, "/items", "GET", undefined, true);
  let shown = 0;
  for (const item of data.items as any[]) {
    if (item.deleted || item.type !== "login") continue;
    let plain: any;
    try { plain = await decryptItem(vaultKeyB64, item.id, item.ciphertextB64, item.wrappedItemKeyB64); }
    catch { continue; }
    const matches = (plain.uris ?? []).some((u: { uri: string; match?: MatchType }) =>
      uriMatches(u.uri, u.match ?? "domain", host));
    if (!matches) continue;
    shown++;
    const row = document.createElement("div");
    row.className = "item";
    const label = document.createElement("span");
    label.textContent = `${plain.name} — ${plain.username ?? ""}`;
    const btn = document.createElement("button");
    btn.textContent = "Fill";
    btn.addEventListener("click", async () => {
      await chrome.tabs.sendMessage(tab.id, { type: "FILL_CREDENTIAL", username: plain.username ?? "", password: plain.password ?? "" });
      window.close();
    });
    row.append(label, btn);
    container.append(row);
  }
  if (!shown) container.textContent = "No matching logins for this site.";
}

document.getElementById("unlock")?.addEventListener("click", unlock);
document.getElementById("lock")?.addEventListener("click", () => {
  accessToken = null; vaultKeyB64 = null;
  (document.getElementById("locked") as HTMLDivElement).hidden = false;
  (document.getElementById("unlocked") as HTMLDivElement).hidden = true;
});

chrome.storage.local.get(["openpass.serverUrl", "openpass.email"], (r: Record<string, string>) => {
  if (r["openpass.serverUrl"]) $("server").value = r["openpass.serverUrl"];
  if (r["openpass.email"]) $("email").value = r["openpass.email"];
});
