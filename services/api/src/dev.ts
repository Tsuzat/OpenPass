import { createApp } from "./app";
import { MemoryStore } from "./store/memory";

// Local dev server (in-memory, data lost on restart): bun run src/dev.ts
// Production uses src/index.ts on Cloudflare Workers with D1.
const app = createApp(new MemoryStore(), { pbkdf2Iterations: 100_000 });
export default { port: 8787, fetch: app.fetch };
