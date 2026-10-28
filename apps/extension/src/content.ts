// Content script: detects credential forms, asks the background worker for a
// match after unlock, and fills only on explicit user action from the popup.
// Security: matching is by registrable domain in the background worker; this
// script only reports field shapes + hostname, never field values, and filling
// requires the FILL_CREDENTIAL message (user gesture in the popup).

interface FillMessage { type: "FILL_CREDENTIAL"; username: string; password: string }

function findCredentialPair(): { user: HTMLInputElement; pass: HTMLInputElement } | null {
  const pass = document.querySelector<HTMLInputElement>("input[type='password']:not([autocomplete='new-password'])")
    ?? document.querySelector<HTMLInputElement>("input[type='password']");
  if (!pass) return null;
  const form = pass.closest("form");
  const scope: ParentNode = form ?? document;
  const user = scope.querySelector<HTMLInputElement>(
    "input[autocomplete='username'], input[type='email'], input[name*='user' i], input[type='text']",
  );
  return user ? { user, pass } : null;
}

function setValue(input: HTMLInputElement, value: string) {
  const proto = Object.getPrototypeOf(input) as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  if (setter) setter.call(input, value); else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

chrome.runtime.sendMessage({ type: "FORM_DETECTED", hasCredentials: !!findCredentialPair(), host: location.hostname });

chrome.runtime.onMessage.addListener((msg: FillMessage) => {
  if (msg?.type !== "FILL_CREDENTIAL") return;
  const pair = findCredentialPair();
  if (!pair) return;
  setValue(pair.user, msg.username);
  setValue(pair.pass, msg.password);
});
