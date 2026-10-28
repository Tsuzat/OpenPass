/**
 * Offline cache. Stores ONLY what the server stores: ciphertext items, wrapped keys,
 * KDF params, sync cursor. No plaintext, no vault key, no master password — so the
 * cache has the same confidentiality as the server database.
 * IndexedDB in browsers; in-memory fallback outside browsers (tests).
 */

export interface CachedSession {
  email: string;
  serverUrl: string;
  wrappedVaultKeyB64: string;
  recoveryWrappedVaultKeyB64: string;
  kdfSaltB64: string;
  kdfParamsJson: string;
}
export interface CachedItem {
  id: string; type: string; ciphertextB64: string; wrappedItemKeyB64: string;
  revision: number; deleted: boolean; updatedAt: string; dirty: boolean;
}

const DB_NAME = "openpass";
const mem = { session: null as CachedSession | null, items: new Map<string, CachedItem>(), cursor: null as string | null };
const hasIdb = typeof indexedDB !== "undefined";

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const d = req.result;
      d.createObjectStore("kv");
      d.createObjectStore("items", { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return db().then((d) => new Promise<T>((resolve, reject) => {
    const r = fn(d.transaction(store, mode).objectStore(store));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }));
}

export const offlineStore = {
  async saveSession(s: CachedSession | null): Promise<void> {
    if (!hasIdb) { mem.session = s; return; }
    if (s) await tx("kv", "readwrite", (st) => st.put(s, "session"));
    else await tx("kv", "readwrite", (st) => st.delete("session"));
  },
  async loadSession(): Promise<CachedSession | null> {
    if (!hasIdb) return mem.session;
    return (await tx("kv", "readonly", (st) => st.get("session"))) ?? null;
  },
  async putItem(item: CachedItem): Promise<void> {
    if (!hasIdb) { mem.items.set(item.id, item); return; }
    await tx("items", "readwrite", (st) => st.put(item));
  },
  async putItems(items: CachedItem[]): Promise<void> { for (const i of items) await offlineStore.putItem(i); },
  async removeItem(id: string): Promise<void> {
    if (!hasIdb) { mem.items.delete(id); return; }
    await tx("items", "readwrite", (st) => st.delete(id));
  },
  async allItems(): Promise<CachedItem[]> {
    if (!hasIdb) return [...mem.items.values()];
    return tx("items", "readonly", (st) => st.getAll());
  },
  async dirtyItems(): Promise<CachedItem[]> { return (await offlineStore.allItems()).filter((i) => i.dirty); },
  async clear(): Promise<void> {
    if (!hasIdb) { mem.items.clear(); mem.session = null; mem.cursor = null; return; }
    await tx("items", "readwrite", (st) => st.clear());
    await tx("kv", "readwrite", (st) => st.clear());
  },
  async setCursor(c: string | null): Promise<void> {
    if (!hasIdb) { mem.cursor = c; return; }
    if (c) await tx("kv", "readwrite", (st) => st.put(c, "cursor")); else await tx("kv", "readwrite", (st) => st.delete("cursor"));
  },
  async getCursor(): Promise<string | null> {
    if (!hasIdb) return mem.cursor;
    return (await tx("kv", "readonly", (st) => st.get("cursor"))) ?? null;
  },
};
