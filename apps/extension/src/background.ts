/// <reference types="chrome" />
// Background service worker: holds session state, talks to the self-hosted API.
// Vault keys live only in memory here (never in chrome.storage). Auto-lock clears them.

export interface SessionState { serverUrl: string; unlocked: boolean; lockedAt: number | null }
let session: SessionState = { serverUrl: "", unlocked: false, lockedAt: null };

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "GET_STATE") sendResponse(session);
  if (msg?.type === "SET_SERVER") { session.serverUrl = String(msg.url ?? ""); sendResponse(session); }
  if (msg?.type === "LOCK") { session = { ...session, unlocked: false, lockedAt: Date.now() }; sendResponse(session); }
  return true;
});

// Content script + popup are bundled separately; keep this worker dependency-free.
console.log("OpenPass background worker started");
