import { useCallback, useEffect, useState } from "react";
import { checkHealth, getServerUrl, setServerUrl } from "./lib/api";
import * as vault from "./lib/vault";

type View = "auth" | "vault";

export default function App() {
  const [server, setServer] = useState(getServerUrl());
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [view, setView] = useState<View>("auth");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [items, setItems] = useState<vault.VaultItemSummary[]>([]);
  const [newItem, setNewItem] = useState({ name: "", username: "", password: "", uri: "" });

  useEffect(() => { checkHealth().then(setHealthy); }, [server]);

  const refreshItems = useCallback(async () => {
    try { setItems(await vault.listItems()); } catch (e) { setError(String((e as Error).message)); }
  }, []);

  async function submit() {
    setError(""); setBusy("Deriving keys locally (Argon2id)…");
    // let the busy message paint before the synchronous WASM KDF blocks the thread
    await new Promise((r) => setTimeout(r, 50));
    try {
      if (mode === "register") {
        const { recoveryKeyText } = await vault.register(email, password);
        setRecoveryKey(recoveryKeyText);
      } else {
        await vault.login(email, password);
      }
      setPassword("");
      setView("vault");
      await refreshItems();
    } catch (e) {
      const code = (e as Error & { code?: string }).code ?? (e as Error).message;
      setError(
        code === "DEVICE_APPROVAL_REQUIRED"
          ? "New device: approve this device from an already-signed-in device, then log in again."
          : code === "INVALID_CREDENTIALS" ? "Invalid email or master password."
          : code === "EMAIL_TAKEN" ? "An account with this email already exists."
          : `Failed: ${code}`,
      );
    } finally { setBusy(""); }
  }

  async function addItem() {
    setBusy("Encrypting & syncing…");
    try {
      await vault.createLoginItem(newItem.name, newItem.username, newItem.password, newItem.uri);
      setNewItem({ name: "", username: "", password: "", uri: "" });
      await refreshItems();
    } catch (e) { setError(String((e as Error).message)); } finally { setBusy(""); }
  }

  const input = { display: "block", width: "100%", marginTop: 4 } as const;

  if (view === "vault") {
    return (
      <main style={{ fontFamily: "system-ui", maxWidth: 640, margin: "6vh auto", padding: 24 }}>
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h1>🔓 OpenPass Vault</h1>
          <button onClick={() => { vault.lock(); setItems([]); setView("auth"); }}>Lock</button>
        </header>
        {recoveryKey && (
          <div style={{ border: "2px solid #c00", padding: 12, marginBottom: 16 }}>
            <strong>Save your Recovery Key now — it is shown once and is the ONLY way back in if you forget your master password:</strong>
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{recoveryKey}</pre>
            <button onClick={() => setRecoveryKey("")}>I saved it</button>
          </div>
        )}
        <h2>Items ({items.length})</h2>
        {items.length === 0 && <p>No items yet.</p>}
        <ul>
          {items.map((i) => (
            <li key={i.id}><strong>{i.name}</strong> <span style={{ color: "#888" }}>{i.type}</span>
              {i.type === "login" && <span> — {String(i.plaintext.username ?? "")}</span>}
            </li>
          ))}
        </ul>
        <h3>Add login</h3>
        <label>Name<input style={input} value={newItem.name} onChange={(e) => setNewItem({ ...newItem, name: e.target.value })} /></label>
        <label>Username<input style={input} value={newItem.username} onChange={(e) => setNewItem({ ...newItem, username: e.target.value })} /></label>
        <label>Password<input style={input} type="password" value={newItem.password} onChange={(e) => setNewItem({ ...newItem, password: e.target.value })} /></label>
        <label>URL<input style={input} value={newItem.uri} onChange={(e) => setNewItem({ ...newItem, uri: e.target.value })} /></label>
        <button onClick={addItem} disabled={!newItem.name || !!busy}>Add encrypted item</button>
        {busy && <p>{busy}</p>}
        {error && <p style={{ color: "#c00" }}>{error}</p>}
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
      <p>Server: {healthy === null ? "checking…" : healthy ? "✅ reachable" : "❌ unreachable — start it with `bun run dev:api`"}</p>
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
