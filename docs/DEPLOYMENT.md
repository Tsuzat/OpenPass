# Self-Hosting on Cloudflare (single click / one command)

## One-command path

```bash
git clone https://github.com/<org>/openpass && cd openpass
bun install
bun run setup   # wrangler login → creates D1 + R2 → applies migrations → generates secrets → deploys
```

`setup` (services/api/scripts/setup.ts) runs, idempotently:
1. `wrangler d1 create openpass` (skips if binding resolves)
2. `wrangler r2 bucket create openpass-attachments`
3. `wrangler d1 migrations apply openpass --remote`
4. Generates `SESSION_PEPPER` → `wrangler secret put`
5. `wrangler deploy`

Environment variables for every component are documented in `.env.example`
files (repo root has the index). The Worker uses `wrangler.jsonc` vars +
`wrangler secret put` in production and `.dev.vars` locally — see
`services/api/.env.example`. Clients take their default server URL from
build-time env (`VITE_SERVER_URL` web, `OPENPASS_API_URL` Android) with
in-app configuration taking precedence.

## Config (`wrangler.jsonc` vars)

| Var | Default | Meaning |
|---|---|---|
| `ALLOW_REGISTRATION` | `true` | Set `false` to freeze signups on a private instance. |
| `TURNSTILE_SECRET` | unset | If set, registration requires Turnstile token. |

## Notes

- Workers run Cloudflare's `workerd`, not Bun/Deno. Bun is the local toolchain only.
- Updates: `git pull && bunx wrangler d1 migrations apply openpass --remote && bunx wrangler deploy`.
- Backups: D1 export (`wrangler d1 export`) contains only ciphertext + auth hashes.
