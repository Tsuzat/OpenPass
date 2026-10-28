/// <reference types="chrome" />
const serverInput = document.getElementById("server") as HTMLInputElement;
const status = document.getElementById("status") as HTMLParagraphElement;

chrome.storage.local.get(["openpass.serverUrl"], (r) => {
  if (r["openpass.serverUrl"]) serverInput.value = String(r["openpass.serverUrl"]);
});
document.getElementById("save")?.addEventListener("click", async () => {
  const url = serverInput.value.replace(/\/$/, "");
  await chrome.storage.local.set({ "openpass.serverUrl": url });
  try {
    const res = await fetch(`${url}/health`);
    const data = (await res.json()) as { ok?: boolean };
    status.textContent = data.ok ? "Server reachable. Unlock arrives in Phase 2 (WASM core)." : "Server responded unexpectedly.";
  } catch { status.textContent = "Server unreachable."; }
});
