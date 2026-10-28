#!/usr/bin/env bash
# Regenerate Swift + Kotlin UniFFI bindings and the WASM package from crates/openpass-core.
# Requirements: cargo, rustup (wasm32 target), wasm-pack.
set -euo pipefail
cd "$(dirname "$0")/.."
CORE=crates/openpass-core
ROOT=$PWD

echo "==> Building core with UniFFI"
cargo build --manifest-path $CORE/Cargo.toml --features uniffi

LIB=$ROOT/$CORE/target/debug/libopenpass_core.dylib
[ -f "$LIB" ] || LIB=$ROOT/$CORE/target/debug/libopenpass_core.so

echo "==> Swift bindings -> apps/macos/Sources/OpenPassCoreFFI"
# uniffi-bindgen runs `cargo metadata` from the cwd — it must run inside the crate directory.
(cd "$CORE" && cargo run --features bindgen --bin uniffi-bindgen -- \
  generate --library "$LIB" --language swift --out-dir "$ROOT/apps/macos/Sources/OpenPassCoreFFI")

echo "==> Kotlin bindings -> apps/android/.../core/ffi"
TMP=$(mktemp -d)
(cd "$CORE" && cargo run --features bindgen --bin uniffi-bindgen -- \
  generate --library "$LIB" --language kotlin --config "$ROOT/$CORE/uniffi.toml" --out-dir "$TMP")
mkdir -p apps/android/app/src/main/java/app/openpass/core/ffi
cp "$TMP/app/openpass/core/ffi/openpass_core.kt" apps/android/app/src/main/java/app/openpass/core/ffi/openpass_core.kt
rm -rf "$TMP"

echo "==> XCFramework (macOS, arm64 + x86_64) — requires Xcode toolchain"
if command -v xcodebuild >/dev/null 2>&1 && xcodebuild -version >/dev/null 2>&1; then
  cargo build --manifest-path $CORE/Cargo.toml --features uniffi --release --target aarch64-apple-darwin
  echo "    (assemble XCFramework in Xcode from target/aarch64-apple-darwin/release/libopenpass_core.a — see apps/macos/README.md)"
else
  echo "    skipped: Xcode not available"
fi

echo "==> WASM package -> apps/web/src/lib/wasm"
# Uses cargo + wasm-bindgen CLI directly (matching the wasm-bindgen version in Cargo.lock).
# wasm-pack is an alternative but is sensitive to crate layout; the direct path is reproducible.
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --manifest-path $CORE/Cargo.toml --lib --release --target wasm32-unknown-unknown --features wasm
mkdir -p apps/web/src/lib/wasm
wasm-bindgen --target web --out-dir "$ROOT/apps/web/src/lib/wasm" --out-name openpass_core \
  "$ROOT/$CORE/target/wasm32-unknown-unknown/release/openpass_core.wasm"

echo "Done."
