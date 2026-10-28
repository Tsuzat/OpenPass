import { useCallback, useEffect, useRef, useState } from "react";
import { checkHealth, getServerUrl, setServerUrl } from "./lib/api";
import * as vault from "./lib/vault";

type ItemKind = "login" | "card" | "secure_note" | "totp" | "identity";
const input = { display: "block", width: "100%", marginTop: 4 } as const;

export default function App() {
  const [server, setServer] = useState(getServerUrl());
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [view, setView] = useState<"auth" | "vault">("auth");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [offline, setOffline] = useState(false);
  const [items, setItems] = useState<vault.VaultItemSummary[]>([]);
  const [codes, setCodes] = useState<Record<string, string>>({});
  const [kind, setKind] = useState<ItemKind>("login");
  const [form, setForm] = useState<Record<string, string>>({ name: "", username: "", password: "", uri: "", number: "", cardholder: "", expMonth: "", expYear: "", cvv: "", content: "", secretBase32: "", issuer: "", account: "", firstName: "", lastName: "", phone: "" });
  const lockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => { checkHealth().then(setHealthy); }, [server]);

  const doLock = useCallback(() => { vault.lock(); setItems([]); setView("auth"); }, []);

  // Auto-lock after 5 minutes without activity while unlocked.
  useEffect(() => {
    if (view !== "vault") return;
    const arm = () => {
      if (lockTimer.current) clearTimeout(lockTimer.current);
      lockTimer.current = setTimeout(doLock, 5 * 60 * 1000);
    };
    arm();
    const events = ["mousemove", "keydown", "click"] as const;
    events.forEach((e) => window.addEventListener(e, arm));
    return () => { events.forEach((e) => window.removeEventListener(e, arm)); if (lockTimer.current) clearTimeout(lockTimer.current); };
  }, [view, doLock]);

  const refreshItems = useCallback(async () => {
    try { setItems(await vault.listItems()); setOffline(vault.isOffline()); }
    catch (e) { setError(String((e as Error).message)); }
  }, []);

  // Live TOTP codes for authenticator items (regenerated locally, seeds never leave the vault).
  useEffect(() => {
    if (view !== "vault") return;
    const totpItems = items.filter((i) => i.type === "totp");
    if (!totpItems.length) return;
    let alive = true;
    const tick = async () => {
      const next: Record<string, string> = {};
      for (const i of totpItems) {
        try { next[i.id] = await vault.currentTotp(String(i.plaintext.secretBase32)); } catch { /* ignore */ }
      }
      if (alive) setCodes(next);
    };
    tick();
    const t = setInterval(tick, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [items, view]);

  async function submit() {
    setError(""); setBusy("Deriving keys locally (Argon2id, in a Web Worker)…");
    await new Promise((r) => setTimeout(r, 50));
    try {
      if (mode === "register") {
        const { recoveryKeyText } = await vault.register(email, password);
        setRecoveryKey(recoveryKeyText);
        setOffline(false);
      } else {
        const { offline: off } = await vault.login(email, password);
        setOffline(off);
      }
      setPassword("");
      setView("vault");
      await refreshItems();
    } catch (e) {
      const code = (e as Error & { code?: string }).code ?? (e as Error).message;
      setError(
        code === "DEVICE_APPROVAL_REQUIRED" ? "New device: approve this device from an already-signed-in device, then log in again."
        : code === "INVALID_CREDENTIALS" ? "Invalid email or master password."
        : code === "EMAIL_TAKEN" ? "An account with this email already exists."
        : code === "NETWORK" ? "Server unreachable and no cached vault for this account on this device."
        : `Failed: ${code}`,
      );
    } finally { setBusy(""); }
  }

  async function addItem() {
    setBusy("Encrypting & syncing…");
    try {
      const f = form;
      if (kind === "login") await vault.createItem("login", { name: f.name, username: f.username, password: f.password, uris: f.uri ? [{ uri: f.uri, match: "domain" }] : [], notes: "", totpId: null, customFields: [] });
      else if (kind === "card") await vault.createItem("card", { name: f.name, cardholder: f.cardholder, number: f.number, brand: "", expMonth: f.expMonth, expYear: f.expYear, cvv: f.cvv, notes: "" });
      else if (kind === "secure_note") await vault.createItem("secure_note", { name: f.name, content: f.content });
      else if (kind === "totp") await vault.createItem("totp", { name: f.name, issuer: f.issuer, account: f.account, secretBase32: f.secretBase32.replace(/\s/g, "").toUpperCase(), algorithm: "SHA1", digits: 6, period: 30 });
      else await vault.createItem("identity", { name: f.name, firstName: f.firstName, lastName: f.lastName, email: f.account, phone: f.phone, address1: "", address2: "", city: "", state: "", postcode: "", country: "" });
      setForm({ ...form, name: "", username: "", password: "", uri: "", number: "", content: "", secretBase32: "" });
      await refreshItems();
    } catch (e) { setError(String((e as Error).message)); } finally { setBusy(""); }
  }

  if (view === "vault") {
    return (
      <main style={{ fontFamily: "system-ui", maxWidth: 640, margin: "6vh auto", padding: 24 }}>
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h1>🔓 OpenPass Vault {offline && <span style={{ fontSize: 14, color: "#b58900" }}>(offline)</span>}</h1>
          <button onClick={doLock}>Lock</button>
        </header>
        {recoveryKey && (
          <div style={{ border: "2px solid #c00", padding: 12, marginBottom: 16 }}>
            <strong>Save your Recovery Key now — shown once; it is the ONLY way back in if you forget your master password:</strong>
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{recoveryKey}</pre>
            <button onClick={() => setRecoveryKey("")}>I saved it</button>
          </div>
        )}
        <h2>Items ({items.length})</h2>
        {items.length === 0 && <p>No items yet. Add one below — it is encrypted on this device before sync.</p>}
        <ul>
          {items.map((i) => (
            <li key={i.id}>
              <strong>{i.name}</strong> <span style={{ color: "#888" }}>{i.type}</span>
              {i.type === "login" && <span> — {String(i.plaintext.username ?? "")}</span>}
              {i.type === "card" && <span> — •••• {String(i.plaintext.number ?? "").slice(-4)}</span>}
              {i.type === "totp" && <span> — <code style={{ fontSize: 16 }}>{codes[i.id] ?? "······"}</code> <span style={{ color: "#888" }}>{String(i.plaintext.issuer ?? "")} {String(i.plaintext.account ?? "")}</span></span>}
              {i.type === "secure_note" && <span> — {String(i.plaintext.content ?? "").slice(0, 40)}…</span>}
            </li>
          ))}
        </ul>

        <h3>Add item</h3>
        <label>Type
          <select style={input} value={kind} onChange={(e) => setKind(e.target.value as ItemKind)}>
            <option value="login">Login</option><option value="card">Payment card</option>
            <option value="secure_note">Secure note</option><option value="totp">Authenticator (TOTP)</option>
            <option value="identity">Identity / address</option>
          </select>
        </label>
        <label>Name<input style={input} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        {kind === "login" && <>
          <label>Username<input style={input} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Password
            <span style={{ display: "flex", gap: 6 }}>
              <input style={{ ...input, flex: 1 }} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <button type="button" onClick={async () => setForm({ ...form, password: await vault.makePassword(20) })}>Generate</button>
            </span>
          </label>
          <label>URL<input style={input} value={form.uri} onChange={(e) => setForm({ ...form, uri: e.target.value })} /></label>
        </>}
        {kind === "card" && <>
          <label>Cardholder<input style={input} value={form.cardholder} onChange={(e) => setForm({ ...form, cardholder: e.target.value })} /></label>
          <label>Number<input style={input} value={form.number} onChange={(e) => setForm({ ...form, number: e.target.value })} /></label>
          <label>Expiry month / year<input style={input} value={form.expMonth} onChange={(e) => setForm({ ...form, expMonth: e.target.value })} placeholder="MM" /></label>
          <input style={input} value={form.expYear} onChange={(e) => setForm({ ...form, expYear: e.target.value })} placeholder="YYYY" />
          <label>CVV<input style={input} value={form.cvv} onChange={(e) => setForm({ ...form, cvv: e.target.value })} /></label>
        </>}
        {kind === "secure_note" && <label>Content<textarea style={input} rows={5} value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} /></label>}
        {kind === "totp" && <>
          <label>Issuer<input style={input} value={form.issuer} onChange={(e) => setForm({ ...form, issuer: e.target.value })} /></label>
          <label>Account<input style={input} value={form.account} onChange={(e) => setForm({ ...form, account: e.target.value })} /></label>
          <label>Secret (Base32)
            <span style={{ display: "flex", gap: 6 }}>
              <input style={{ ...input, flex: 1 }} value={form.secretBase32} onChange={(e) => setForm({ ...form, secretBase32: e.target.value })} placeholder="JBSWY3DPEHPK3PXP" />
              <button type="button" onClick={async () => setForm({ ...form, secretBase32: await vault.newTotpSecret() })}>Generate</button>
            </span>
          </label>
        </>}
        {kind === "identity" && <>
          <label>First name<input style={input} value={form.firstName} onChange={(e) => setForm({ ...form, firstName: e.target.value })} /></label>
          <label>Last name<input style={input} value={form.lastName} onChange={(e) => setForm({ ...form, lastName: e.target.value })} /></label>
          <label>Email<input style={input} value={form.account} onChange={(e) => setForm({ ...form, account: e.target.value })} /></label>
          <label>Phone<input style={input} value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} /></label>
        </>}
        <button onClick={addItem} disabled={!form.name || !!busy} style={{ marginTop: 8 }}>Add encrypted item</button>
        {busy && <p>{busy}</p>}
        {error && <p style={{ color: "#c00" }}>{error}</p>}
        <p style={{ color: "#888", fontSize: 12 }}>Auto-locks after 5 minutes of inactivity. Offline items queue locally and sync on next unlock.</p>
      </main>
    );
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 420, margin: "10vh auto", padding: 24 }}>
      <h1>🔒 OpenPass</h1>
      <p>Zero-knowledge web vault. Your master password never leaves this device — only a derived verifier is sent to the server.</p>
      <label style={{ display: "block", marginBottom: 12 }}>
        Server URL
        <input value={server} onChange={(e) => { setServer(e.target.value); setServerUrl(e.target.value); }} style={input} />
      </label>
      <p>Server: {healthy === null ? "checking…" : healthy ? "✅ reachable" : "❌ unreachable — start it with `bun run dev:api` (offline unlock works if this device has a cached vault)"}</p>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button onClick={() => setMode("login")} disabled={mode === "login"}>Log in</button>
        <button onClick={() => setMode("register")} disabled={mode === "register"}>Create account</button>
      </div>
      <label style={{ display: "block", marginBottom: 12 }}>Email<input style={input} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      <label style={{ display: "block", marginBottom: 12 }}>
        Master password (min. 12 chars recommended)
        <input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <button onClick={submit} disabled={!email || password.length < 8 || !!busy}>
        {mode === "register" ? "Create vault" : "Unlock"}
      </button>
      {busy && <p>{busy}</p>}
      {error && <p style={{ color: "#c00" }}>{error}</p>}
    </main>
  );
}
