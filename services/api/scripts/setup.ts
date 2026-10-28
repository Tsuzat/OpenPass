/**
 * One-command self-host setup: creates D1 + R2, patches wrangler.jsonc with the real
 * database_id, applies migrations, sets secrets, deploys. Idempotent where Wrangler allows.
 * Run from services/api: bun run setup
 */
import { $ } from "bun";
import { readFile, writeFile } from "node:fs/promises";

const run = async (cmd: string[], optional = false) => {
  console.log(`$ ${cmd.join(" ")}`);
  try { await $`${cmd}`; } catch { if (!optional) throw new Error(`failed: ${cmd.join(" ")}`); console.log("(skipped — may already exist)"); }
};

console.log("OpenPass self-host setup — log in to Cloudflare in your browser if prompted.");
await run(["bunx", "wrangler", "d1", "create", "openpass"], true);
await run(["bunx", "wrangler", "r2", "bucket", "create", "openpass-attachments"], true);

// Resolve the real database_id and patch wrangler.jsonc (template ships a placeholder).
const list = await $`bunx wrangler d1 list --json`.json() as { name: string; uuid: string }[];
const db = list.find((d) => d.name === "openpass");
if (!db) throw new Error("D1 database 'openpass' not found after create");
const cfgPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
const cfg = await readFile(cfgPath, "utf8");
await writeFile(cfgPath, cfg.replace(/"database_id":\s*"[^"]*"/, `"database_id": "${db.uuid}"`));
console.log(`Patched wrangler.jsonc database_id -> ${db.uuid}`);

await run(["bunx", "wrangler", "d1", "migrations", "apply", "openpass", "--remote"]);

const pepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
const proc = Bun.spawn(["bunx", "wrangler", "secret", "put", "SESSION_PEPPER"], { stdin: "pipe", stdout: "inherit", stderr: "inherit" });
proc.stdin.write(pepper);
proc.stdin.end();
await proc.exited;

await run(["bunx", "wrangler", "deploy"]);
console.log("\nDone. Registration is OPEN by default — set ALLOW_REGISTRATION=false in wrangler.jsonc to close it.");
console.log("Back up your Recovery Key during signup: there is no email password reset, by design.");
