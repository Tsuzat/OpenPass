// Content script: detects credential forms and requests fill from the background worker.
// Security: never fill when the registrable domain does not match the saved URI match rule,
// and never exfiltrate page data — only field *shapes* are reported.

function detectCredentialForms(): number {
  let count = 0;
  document.querySelectorAll<HTMLInputElement>("input[type='password']").forEach((pw) => {
    const form = pw.closest("form");
    const user = form?.querySelector<HTMLInputElement>(
      "input[autocomplete='username'], input[type='email'], input[type='text']",
    );
    if (user) count += 1;
  });
  return count;
}

chrome.runtime.sendMessage({ type: "FORM_DETECTED", count: detectCredentialForms(), host: location.hostname });
