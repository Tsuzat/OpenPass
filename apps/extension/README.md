# OpenPass Browser Extension

Manifest V3 for Chrome (`manifest.json`) and Firefox (`manifest.firefox.json`, build:firefox).
Safari: wrap the Chrome build with Xcode's Safari Web Extension converter inside the macOS app project.

```bash
bun install
bun run build          # -> dist/ (Chrome)
bun run build:firefox  # -> dist-firefox/
```

Load unpacked in Chrome (`chrome://extensions` → Developer mode) or Firefox (`about:debugging`).
Fill logic + WASM crypto core unlock arrive in Phase 2; keys are never persisted to extension storage.
