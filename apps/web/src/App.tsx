import { useCallback, useEffect, useRef, useState } from "react";
import { checkHealth, getServerUrl, setServerUrl } from "./lib/api";
import * as vault from "./lib/vault";

type ItemKind = "login" | "card" | "secure_note" | "totp" | "identity" | "file" | "passkey";
const input = { display: "block", width: "100%", marginTop: 4 } as const;

export default function App() {
  const [server, setServer] = useState(getServerUrl());
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [view, setView] = useState<"auth" | "vault">("auth");
  const [mode, setMode] = useState<"login" | "register" | "recover">("login");
  const [recoveryInput, setRecoveryInput] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [search, setSearch] = useState("");
  const [tagFilter, setTagFilter] = useState("");
  const [folderList, setFolderList] = useState<vault.Folder[]>([]);
  const [folderFilter, setFolderFilter] = useState<string>(""); // "" all, "none" unfiled, else folder id
  const [newFolder, setNewFolder] = useState("");
  const [trash, setTrash] = useState<vault.VaultItemSummary[]>([]);
  const [history, setHistory] = useState<vault.HistoryEntry[]>([]);
  const [devices, setDevices] = useState<vault.DeviceInfoRow[]>([]);
  const [pendingDevices, setPendingDevices] = useState<vault.DeviceInfoRow[]>([]);
  const [selected, setSelected] = useState<vault.VaultItemSummary | null>(null);
  const [reveal, setReveal] = useState(false);
  const [pwChange, setPwChange] = useState({ current: "", next: "" });
  const [editForm, setEditForm] = useState<Record<string, string>>({});
  const [transferPassword, setTransferPassword] = useState("");
  const [transferMsg, setTransferMsg] = useState("");
  const [pendingImport, setPendingImport] = useState<{ fresh: Record<string, unknown>[]; duplicates: number; source: string } | null>(null);
  const [pwMsg, setPwMsg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [offline, setOffline] = useState(false);
  const [items, setItems] = useState<vault.VaultItemSummary[]>([]);
  const [codes, setCodes] = useState<Record<string, string>>({});
  const [kind, setKind] = useState<ItemKind>("login");
  const [form, setForm] = useState<Record<string, string>>({ name: "", tags: "", username: "", password: "", uri: "", number: "", cardholder: "", expMonth: "", expYear: "", cvv: "", content: "", secretBase32: "", issuer: "", account: "", firstName: "", lastName: "", phone: "" });
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

  useEffect(() => {
    if (!selected) { setEditForm({}); return; }
    const p = selected.plaintext;
    setEditForm({
      name: selected.name, username: String(p.username ?? ""), password: String(p.password ?? ""),
      uri: String(((p.uris as { uri: string }[] | undefined)?.[0]?.uri) ?? ""),
      cardholder: String(p.cardholder ?? ""), number: String(p.number ?? ""), expMonth: String(p.expMonth ?? ""),
      expYear: String(p.expYear ?? ""), cvv: String(p.cvv ?? ""), content: String(p.content ?? ""),
      issuer: String(p.issuer ?? ""), account: String(p.account ?? ""), secretBase32: String(p.secretBase32 ?? ""),
      firstName: String(p.firstName ?? ""), lastName: String(p.lastName ?? ""), phone: String(p.phone ?? ""), tags: ((p.tags as string[] | undefined) ?? []).join(", "), folderId: String(p.folderId ?? ""),
    });
  }, [selected]);

  const refreshItems = useCallback(async () => {
    try {
      setItems(await vault.listItems()); setOffline(vault.isOffline());
      setFolderList(await vault.getFolders());
      setTrash(await vault.listTrash().catch(() => []));
      setDevices(await vault.listDevices().catch(() => []));
      setPendingDevices(await vault.listPendingDevices().catch(() => []));
    }
    catch (e) { setError(String((e as Error).message)); }
  }, []);

  const filteredItems = () => items.filter((i) => {
    const matchesSearch = !search || `${i.name} ${String(i.plaintext.username ?? "")} ${String(i.plaintext.issuer ?? "")}`.toLowerCase().includes(search.toLowerCase());
    const matchesTag = !tagFilter || (((i.plaintext.tags as string[] | undefined) ?? []).includes(tagFilter));
    const matchesFolder = folderFilter === "" ? true
      : folderFilter === "none" ? !i.plaintext.folderId
      : i.plaintext.folderId === folderFilter;
    return matchesSearch && matchesTag && matchesFolder;
  });

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
      if (mode === "recover") {
        await vault.recoverWithRecoveryKey(email, recoveryInput, newPassword);
        setOffline(false);
      } else if (mode === "register") {
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
      if (kind === "login") await vault.createItem("login", { folderId: f.folderId ? f.folderId : null, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), name: f.name, username: f.username, password: f.password, uris: f.uri ? [{ uri: f.uri, match: "domain" }] : [], notes: "", totpId: null, customFields: [] });
      else if (kind === "card") await vault.createItem("card", { folderId: f.folderId ? f.folderId : null, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), name: f.name, cardholder: f.cardholder, number: f.number, brand: "", expMonth: f.expMonth, expYear: f.expYear, cvv: f.cvv, notes: "" });
      else if (kind === "secure_note") await vault.createItem("secure_note", { folderId: f.folderId ? f.folderId : null, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), name: f.name, content: f.content });
      else if (kind === "totp") await vault.createItem("totp", { folderId: f.folderId ? f.folderId : null, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), name: f.name, issuer: f.issuer, account: f.account, secretBase32: f.secretBase32.replace(/\s/g, "").toUpperCase(), algorithm: "SHA1", digits: 6, period: 30 });
      else if (kind === "passkey") await vault.createPasskeyItem(f.name, f.uri, f.username);
      else await vault.createItem("identity", { folderId: f.folderId ? f.folderId : null, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), name: f.name, firstName: f.firstName, lastName: f.lastName, email: f.account, phone: f.phone, address1: "", address2: "", city: "", state: "", postcode: "", country: "" });
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
        <input style={{ ...input, marginBottom: 12 }} placeholder="Search name, username, issuer…" value={search}
          onChange={(e) => setSearch(e.target.value)} />
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
          <button onClick={() => setFolderFilter("")} style={folderFilter === "" ? { fontWeight: 700 } : undefined}>All items</button>
          <button onClick={() => setFolderFilter("none")} style={folderFilter === "none" ? { fontWeight: 700 } : undefined}>Unfiled</button>
          {folderList.map((f) => (
            <span key={f.id}>
              <button onClick={() => setFolderFilter(f.id)} style={folderFilter === f.id ? { fontWeight: 700 } : undefined}>📁 {f.name}</button>
              <button title="Delete folder" onClick={async () => {
                if (!confirm(`Delete folder "${f.name}"? Items keep existing but become unfiled on next edit.`)) return;
                const next = folderList.filter((x) => x.id !== f.id);
                await vault.setFolders(next); setFolderList(next); if (folderFilter === f.id) setFolderFilter("");
              }}>×</button>
            </span>
          ))}
          <input placeholder="New folder" value={newFolder} onChange={(e) => setNewFolder(e.target.value)} style={{ width: 110 }} />
          <button disabled={!newFolder.trim()} onClick={async () => {
            const next = [...folderList, { id: crypto.randomUUID(), name: newFolder.trim() }];
            await vault.setFolders(next); setFolderList(next); setNewFolder("");
          }}>Add folder</button>
        </div>
        {(() => {
          const allTags = [...new Set(items.flatMap((i) => (i.plaintext.tags as string[] | undefined) ?? []))].sort();
          return allTags.length ? (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
              <button onClick={() => setTagFilter("")} disabled={!tagFilter}>All</button>
              {allTags.map((tag) => (
                <button key={tag} onClick={() => setTagFilter(tag === tagFilter ? "" : tag)} style={tag === tagFilter ? { fontWeight: 700 } : undefined}>#{tag}</button>
              ))}
            </div>
          ) : null;
        })()}
        <h2>Items ({filteredItems().length})</h2>
        {items.length === 0 && <p>No items yet. Add one below — it is encrypted on this device before sync.</p>}
        <ul>
          {filteredItems().map((i) => (
            <li key={i.id} onClick={() => { setSelected(i); setReveal(false); }} style={{ cursor: "pointer" }}>
              <strong>{i.name}</strong> <span style={{ color: "#888" }}>{i.type}</span>
              {i.type === "login" && <span> — {String(i.plaintext.username ?? "")}</span>}
              {i.type === "card" && <span> — •••• {String(i.plaintext.number ?? "").slice(-4)}</span>}
              {i.type === "totp" && <span> — <code style={{ fontSize: 16 }}>{codes[i.id] ?? "······"}</code> <span style={{ color: "#888" }}>{String(i.plaintext.issuer ?? "")} {String(i.plaintext.account ?? "")}</span></span>}
              {i.type === "secure_note" && <span> — {String(i.plaintext.content ?? "").slice(0, 40)}…</span>}
              {(((i.plaintext.tags as string[] | undefined) ?? []).length > 0) && <span style={{ color: "#06c" }}> {((i.plaintext.tags as string[]) ?? []).map((tg) => `#${tg}`).join(" ")}</span>}
            </li>
          ))}
        </ul>

        {selected && (
          <div style={{ border: "1px solid #ccc", padding: 12, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0 }}>{selected.name} <span style={{ color: "#888", fontWeight: 400 }}>{selected.type} · rev {selected.revision}</span></h3>
            {selected.type === "login" && <>
              <p>Username: {String(selected.plaintext.username ?? "")}</p>
              <p>Password: <code>{reveal ? String(selected.plaintext.password ?? "") : "••••••••"}</code>{" "}
                <button onClick={() => setReveal(!reveal)}>{reveal ? "Hide" : "Reveal"}</button>{" "}
                <button onClick={() => navigator.clipboard.writeText(String(selected.plaintext.password ?? ""))}>Copy</button></p>
              <p>URL: {((selected.plaintext.uris as { uri: string }[] | undefined)?.[0]?.uri) ?? ""}</p>
            </>}
            {selected.type === "totp" && <p>Code: <code style={{ fontSize: 18 }}>{codes[selected.id] ?? "······"}</code></p>}
            {selected.type === "secure_note" && <pre style={{ whiteSpace: "pre-wrap" }}>{String(selected.plaintext.content ?? "")}</pre>}
            {selected.type === "card" && <p>•••• {String(selected.plaintext.number ?? "").slice(-4)} · {String(selected.plaintext.cardholder ?? "")}</p>}
            <label>Name<input style={input} value={editForm.name ?? ""} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} /></label>
            {selected.type === "login" && <>
              <label>Username<input style={input} value={editForm.username ?? ""} onChange={(e) => setEditForm({ ...editForm, username: e.target.value })} /></label>
              <label>Password<input style={input} value={editForm.password ?? ""} onChange={(e) => setEditForm({ ...editForm, password: e.target.value })} /></label>
              <label>URL<input style={input} value={editForm.uri ?? ""} onChange={(e) => setEditForm({ ...editForm, uri: e.target.value })} /></label>
            </>}
            {selected.type === "card" && <>
              <label>Cardholder<input style={input} value={editForm.cardholder ?? ""} onChange={(e) => setEditForm({ ...editForm, cardholder: e.target.value })} /></label>
              <label>Number<input style={input} value={editForm.number ?? ""} onChange={(e) => setEditForm({ ...editForm, number: e.target.value })} /></label>
              <label>Expiry (MM / YYYY)<input style={input} value={editForm.expMonth ?? ""} onChange={(e) => setEditForm({ ...editForm, expMonth: e.target.value })} /></label>
              <input style={input} value={editForm.expYear ?? ""} onChange={(e) => setEditForm({ ...editForm, expYear: e.target.value })} />
              <label>CVV<input style={input} value={editForm.cvv ?? ""} onChange={(e) => setEditForm({ ...editForm, cvv: e.target.value })} /></label>
            </>}
            {selected.type === "secure_note" && <label>Content<textarea style={input} rows={5} value={editForm.content ?? ""} onChange={(e) => setEditForm({ ...editForm, content: e.target.value })} /></label>}
            {selected.type === "totp" && <>
              <label>Issuer<input style={input} value={editForm.issuer ?? ""} onChange={(e) => setEditForm({ ...editForm, issuer: e.target.value })} /></label>
              <label>Account<input style={input} value={editForm.account ?? ""} onChange={(e) => setEditForm({ ...editForm, account: e.target.value })} /></label>
              <label>Secret (Base32)<input style={input} value={editForm.secretBase32 ?? ""} onChange={(e) => setEditForm({ ...editForm, secretBase32: e.target.value })} /></label>
            </>}
            {selected.type === "identity" && <>
              <label>First name<input style={input} value={editForm.firstName ?? ""} onChange={(e) => setEditForm({ ...editForm, firstName: e.target.value })} /></label>
              <label>Last name<input style={input} value={editForm.lastName ?? ""} onChange={(e) => setEditForm({ ...editForm, lastName: e.target.value })} /></label>
              <label>Phone<input style={input} value={editForm.phone ?? ""} onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })} /></label>
            </>}
            <label>Tags (comma separated)<input style={input} value={editForm.tags ?? ""} onChange={(e) => setEditForm({ ...editForm, tags: e.target.value })} /></label>
            <label>Folder
              <select style={input} value={editForm.folderId ?? ""} onChange={(e) => setEditForm({ ...editForm, folderId: e.target.value })}>
                <option value="">Unfiled</option>
                {folderList.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
              </select>
            </label>
            {selected.type === "file" && (
              <button onClick={async () => {
                const f = await vault.downloadFile(selected);
                const blob = new Blob([f.bytes as BlobPart], { type: f.mimeType });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob); a.download = f.fileName; a.click();
                URL.revokeObjectURL(a.href);
              }}>Download decrypted file ({String(selected.plaintext.sizeBytes ?? "?")} bytes)</button>
            )}
            <div style={{ marginTop: 8 }}>
              <button onClick={async () => setHistory(await vault.getItemHistory(selected.id).catch(() => []))}>Load history</button>
              {history.map((h) => (
                <div key={h.revision} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span>rev {h.revision} · {h.updatedAt} · {String(h.plaintext.name ?? "")}</span>
                  <button onClick={async () => { await vault.restoreHistoryVersion(selected.id, h); setSelected(null); setHistory([]); await refreshItems(); }}>Restore this version</button>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button onClick={async () => {
                const f = editForm;
                const fields: Record<string, unknown> = { name: f.name, tags: (f.tags ?? "").split(",").map((tg) => tg.trim()).filter(Boolean), folderId: f.folderId ? f.folderId : null };
                if (selected.type === "login") Object.assign(fields, { username: f.username, password: f.password, uris: f.uri ? [{ uri: f.uri, match: "domain" }] : [] });
                if (selected.type === "card") Object.assign(fields, { cardholder: f.cardholder, number: f.number, expMonth: f.expMonth, expYear: f.expYear, cvv: f.cvv });
                if (selected.type === "secure_note") Object.assign(fields, { content: f.content });
                if (selected.type === "totp") Object.assign(fields, { issuer: f.issuer, account: f.account, secretBase32: (f.secretBase32 ?? "").replace(/\s/g, "").toUpperCase() });
                if (selected.type === "identity") Object.assign(fields, { firstName: f.firstName, lastName: f.lastName, phone: f.phone });
                await vault.updateItem(selected, fields); setSelected(null); await refreshItems();
              }}>Save changes</button>
              <button style={{ color: "#c00" }} onClick={async () => {
                if (!confirm(`Delete "${selected.name}"? This syncs a tombstone to all devices.`)) return;
                await vault.deleteItem(selected.id); setSelected(null); await refreshItems();
              }}>Delete</button>
              <button onClick={() => setSelected(null)}>Close</button>
            </div>
          </div>
        )}

        <details style={{ marginBottom: 16 }}>
          <summary>Devices ({devices.length}){pendingDevices.length > 0 && <span style={{ color: "#c00" }}> — {pendingDevices.length} awaiting approval</span>}</summary>
          {pendingDevices.map((d) => (
            <div key={d.deviceId} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span>⏳ {d.name} ({d.platform}) — requested {d.createdAt}</span>
              <button onClick={async () => { await vault.approveDevice(d.deviceId); await refreshItems(); }}>Approve</button>
            </div>
          ))}
          {devices.filter((d) => d.status === "approved").map((d) => (
            <div key={d.deviceId} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span>{d.current ? "🟢" : "•"} {d.name} ({d.platform}) — last seen {d.lastSeenAt}</span>
              {!d.current && <button onClick={async () => { if (confirm(`Revoke "${d.name}"? Its sessions will be invalidated.`)) { await vault.revokeDevice(d.deviceId); await refreshItems(); } }}>Revoke</button>}
            </div>
          ))}
          <p style={{ color: "#888", fontSize: 12 }}>New devices cannot sync until approved here. Approving the wrong device gives it your encrypted vault (still protected by your master password).</p>
        </details>

        <details style={{ marginBottom: 16 }}>
          <summary>Change master password</summary>
          <label>Current password<input style={input} type="password" value={pwChange.current} onChange={(e) => setPwChange({ ...pwChange, current: e.target.value })} /></label>
          <label>New password<input style={input} type="password" value={pwChange.next} onChange={(e) => setPwChange({ ...pwChange, next: e.target.value })} /></label>
          <button disabled={offline || !pwChange.current || pwChange.next.length < 8} onClick={async () => {
            setPwMsg("");
            try { await vault.changePassword(pwChange.current, pwChange.next); setPwMsg("Password changed. Other sessions were revoked."); setPwChange({ current: "", next: "" }); }
            catch (e) { setPwMsg(`Failed: ${(e as Error).message}`); }
          }}>Change password</button>
          {offline && <span style={{ color: "#b58900" }}> Requires connection.</span>}
          {pwMsg && <p>{pwMsg}</p>}
        </details>

        <h3>Add item</h3>
        <label>Type
          <select style={input} value={kind} onChange={(e) => setKind(e.target.value as ItemKind)}>
            <option value="login">Login</option><option value="card">Payment card</option>
            <option value="secure_note">Secure note</option><option value="totp">Authenticator (TOTP)</option>
            <option value="identity">Identity / address</option><option value="file">File</option><option value="passkey">Passkey</option>
          </select>
        </label>
        <label>Name<input style={input} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label>Tags (comma separated)<input style={input} value={form.tags ?? ""} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="work, finance" /></label>
        <label>Folder
          <select style={input} value={form.folderId ?? ""} onChange={(e) => setForm({ ...form, folderId: e.target.value })}>
            <option value="">Unfiled</option>
            {folderList.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        </label>
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
        {kind === "passkey" && <>
          <label>Relying Party ID (e.g. github.com)<input style={input} value={form.uri} onChange={(e) => setForm({ ...form, uri: e.target.value })} /></label>
          <label>Username at RP<input style={input} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <p style={{ color: "#888", fontSize: 12 }}>Creates an encrypted synced-passkey item (ES256). Actual site registration happens through the OS credential providers — see docs/PASSKEYS.md.</p>
        </>}
        {kind === "file" ? (
          <label style={{ display: "block", marginTop: 8 }}>Choose file (max ~10 MB in web vault)
            <input type="file" style={input} onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              setBusy("Encrypting & uploading file…");
              try { await vault.uploadFile(file.name, file.type, new Uint8Array(await file.arrayBuffer())); await refreshItems(); }
              catch (err) { setError(String((err as Error).message)); } finally { setBusy(""); }
            }} />
          </label>
        ) : (
          <button onClick={addItem} disabled={!form.name || !!busy} style={{ marginTop: 8 }}>Add encrypted item</button>
        )}
        {busy && <p>{busy}</p>}
        {error && <p style={{ color: "#c00" }}>{error}</p>}
        {trash.length > 0 && (
          <details style={{ marginTop: 16 }}>
            <summary>Trash ({trash.length})</summary>
            {trash.map((i) => (
              <div key={i.id} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span>{i.name} <span style={{ color: "#888" }}>{i.type}</span></span>
                <button onClick={async () => { await vault.restoreItem(i.id); await refreshItems(); }}>Restore</button>
                <button onClick={async () => { await vault.purgeItem(i.id); await refreshItems(); }}>Remove from this device</button>
              </div>
            ))}
            <p style={{ color: "#888", fontSize: 12 }}>Restoring syncs the item back to all devices. Removing only clears this device; the server tombstone remains.</p>
          </details>
        )}

        <details style={{ marginTop: 16 }}>
          <summary>Import / Export</summary>
          <label>Export / import password (for encrypted OpenPass exports only)
            <input style={input} type="password" value={transferPassword} onChange={(e) => setTransferPassword(e.target.value)} />
          </label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
            <button disabled={offline || !transferPassword} onClick={async () => {
              const text = await vault.exportEncrypted(transferPassword);
              const a = document.createElement("a");
              a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
              a.download = "openpass-export.json"; a.click(); URL.revokeObjectURL(a.href);
              setTransferMsg("Encrypted export downloaded.");
            }}>Export encrypted</button>
            <button onClick={async () => {
              if (!confirm("Plaintext export exposes every password. Continue only to a trusted location.")) return;
              const text = await vault.exportPlaintextJson();
              const a = document.createElement("a");
              a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
              a.download = "openpass-plaintext-export.json"; a.click(); URL.revokeObjectURL(a.href);
              setTransferMsg("Plaintext export downloaded — delete it as soon as you are done.");
            }}>Export plaintext (dangerous)</button>
            <label style={{ border: "1px solid #999", padding: "4px 8px", cursor: "pointer" }}>
              Import 1Password / Bitwarden / Zoho / CSV / OpenPass export
              <input type="file" accept=".json,.csv,.1pux" style={{ display: "none" }} onChange={async (e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (!file) return;
                setTransferMsg("Parsing…");
                try {
                  const bytes = new Uint8Array(await file.arrayBuffer());
                  const text = new TextDecoder().decode(bytes);
                  let head: { format?: string } | null = null;
                  try { head = JSON.parse(text) as { format?: string }; } catch { /* not JSON */ }
                  if (head?.format === "openpass-export") {
                    if (!transferPassword) throw new Error("Enter the export password above first");
                    const report = await vault.importEncryptedExport(text, transferPassword);
                    setTransferMsg(`Imported ${report.imported} item(s), skipped ${report.skippedDuplicates} duplicate(s).`);
                    await refreshItems();
                    return;
                  }
                  const { parseImportBytes } = await import("./lib/import");
                  const parsedItems = await parseImportBytes(file.name, bytes);
                  const preview = await vault.previewImport(parsedItems as Record<string, unknown>[]);
                  setPendingImport({ fresh: preview.fresh, duplicates: preview.duplicates.length, source: file.name });
                  setTransferMsg("");
                } catch (err) { setTransferMsg(`Import failed: ${(err as Error).message}`); }
              }} />
            </label>
          </div>
          {transferMsg && <p>{transferMsg}</p>}
          {pendingImport && (
            <div style={{ border: "1px solid #999", padding: 10, marginTop: 8 }}>
              <strong>{pendingImport.source}</strong>: {pendingImport.fresh.length} new item(s)
              {pendingImport.duplicates > 0 && <span>, {pendingImport.duplicates} duplicate(s) will be skipped (same type/name/username/site)</span>}
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button onClick={async () => {
                  const report = await vault.importItems(pendingImport.fresh, false);
                  setTransferMsg(`Imported ${report.imported} item(s) from ${pendingImport.source}.`);
                  setPendingImport(null);
                  await refreshItems();
                }}>Import {pendingImport.fresh.length} item(s)</button>
                <button onClick={() => setPendingImport(null)}>Cancel</button>
              </div>
            </div>
          )}
        </details>

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
        <button onClick={() => setMode("recover")} disabled={mode === "recover"}>Use recovery key</button>
      </div>
      <label style={{ display: "block", marginBottom: 12 }}>Email<input style={input} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      {mode === "recover" ? (
        <>
          <label style={{ display: "block", marginBottom: 12 }}>
            Recovery Key
            <textarea style={input} rows={3} value={recoveryInput} onChange={(e) => setRecoveryInput(e.target.value)} placeholder="XXXX-XXXX-XXXX-…" />
          </label>
          <label style={{ display: "block", marginBottom: 12 }}>
            New master password (min. 12 chars recommended)
            <input style={input} type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
          </label>
          <button onClick={submit} disabled={!email || !recoveryInput || newPassword.length < 8 || !!busy}>Recover &amp; set new password</button>
        </>
      ) : (
        <>
          <label style={{ display: "block", marginBottom: 12 }}>
            Master password (min. 12 chars recommended)
            <input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <button onClick={submit} disabled={!email || password.length < 8 || !!busy}>
            {mode === "register" ? "Create vault" : "Unlock"}
          </button>
        </>
      )}
      {busy && <p>{busy}</p>}
      {error && <p style={{ color: "#c00" }}>{error}</p>}
    </main>
  );
}
