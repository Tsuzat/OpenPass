/** API client for the web vault. Crypto runs in a Web Worker via the Rust core compiled to WASM (Phase 2). */

export function getServerUrl(): string {
  return localStorage.getItem("openpass.serverUrl") ?? "http://localhost:8787";
}
export function setServerUrl(url: string) {
  localStorage.setItem("openpass.serverUrl", url.replace(/\/$/, ""));
}
export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${getServerUrl()}/health`);
    const data = (await res.json()) as { ok?: boolean };
    return res.ok && data.ok === true;
  } catch { return false; }
}
export async function prelogin(email: string): Promise<unknown> {
  const res = await fetch(`${getServerUrl()}/auth/prelogin`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }),
  });
  if (!res.ok) throw new Error(`prelogin failed: ${res.status}`);
  return res.json();
}
