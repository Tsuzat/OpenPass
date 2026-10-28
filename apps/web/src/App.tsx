import { useEffect, useState } from "react";
import { checkHealth, getServerUrl, setServerUrl } from "./lib/api";

export default function App() {
  const [server, setServer] = useState(getServerUrl());
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => { checkHealth().then(setHealthy); }, [server]);

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 420, margin: "10vh auto", padding: 24 }}>
      <h1>🔒 OpenPass</h1>
      <p>Zero-knowledge web vault. Your master password never leaves this device.</p>

      <label style={{ display: "block", marginBottom: 12 }}>
        Server URL
        <input value={server} onChange={(e) => { setServer(e.target.value); setServerUrl(e.target.value); }}
          style={{ display: "block", width: "100%", marginTop: 4 }} />
      </label>
      <p>Server status: {healthy === null ? "checking…" : healthy ? "✅ reachable" : "❌ unreachable — run `bun run dev:api`"}</p>

      <hr />
      <label style={{ display: "block", marginBottom: 12 }}>
        Email
        <input value={email} onChange={(e) => setEmail(e.target.value)} style={{ display: "block", width: "100%", marginTop: 4 }} />
      </label>
      <label style={{ display: "block", marginBottom: 12 }}>
        Master password
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ display: "block", width: "100%", marginTop: 4 }} />
      </label>
      <button disabled title="Enabled when the WASM crypto core lands in Phase 2">Unlock (Phase 2: WASM core)</button>
      <p style={{ color: "#888", fontSize: 13 }}>
        Unlock is intentionally disabled until the Rust core is compiled to WASM — the web vault
        must not reimplement Argon2id/AEAD in ad-hoc JavaScript. See docs/CRYPTO.md.
      </p>
    </main>
  );
}
