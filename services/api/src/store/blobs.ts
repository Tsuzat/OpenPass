/** Object storage for encrypted file blobs. The blob content is chunked AEAD ciphertext (see Rust core). */
export interface BlobStore {
  put(key: string, bytes: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array | null>;
  delete(key: string): Promise<void>;
}

export class MemoryBlobStore implements BlobStore {
  blobs = new Map<string, Uint8Array>();
  async put(key: string, bytes: Uint8Array) { this.blobs.set(key, bytes); }
  async get(key: string) { return this.blobs.get(key) ?? null; }
  async delete(key: string) { this.blobs.delete(key); }
}

interface R2Like {
  put(key: string, value: ArrayBuffer | Uint8Array): Promise<unknown>;
  get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null>;
  delete(key: string): Promise<unknown>;
}

export class R2BlobStore implements BlobStore {
  constructor(private bucket: R2Like) {}
  async put(key: string, bytes: Uint8Array) { await this.bucket.put(key, bytes); }
  async get(key: string) {
    const obj = await this.bucket.get(key);
    return obj ? new Uint8Array(await obj.arrayBuffer()) : null;
  }
  async delete(key: string) { await this.bucket.delete(key); }
}
