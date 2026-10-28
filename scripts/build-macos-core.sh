#!/usr/bin/env bash
# Build the Rust core as a universal macOS static library + XCFramework.
# Output: apps/macos/Frameworks/OpenPassCoreFFI.xcframework (gitignored; regenerate locally)
# Requires: full Xcode (xcodebuild -create-xcframework), rustup targets.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

CORE=crates/openpass-core
OUT=apps/macos/Frameworks
mkdir -p "$OUT"

rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null

for arch in aarch64-apple-darwin x86_64-apple-darwin; do
  echo "==> building $arch"
  cargo build --manifest-path $CORE/Cargo.toml --release --features uniffi --target "$arch"
done

echo "==> lipo universal static lib"
lipo -create \
  "$CORE/target/aarch64-apple-darwin/release/libopenpass_core.a" \
  "$CORE/target/x86_64-apple-darwin/release/libopenpass_core.a" \
  -output "$OUT/libopenpass_core.a"

echo "==> headers"
HDR="$OUT/Headers"
rm -rf "$HDR"; mkdir -p "$HDR"
cp apps/macos/Sources/OpenPassCoreFFI/openpass_coreFFI.h "$HDR/"
# XCFramework expects module.modulemap; UniFFI generates openpass_coreFFI.modulemap
cp apps/macos/Sources/OpenPassCoreFFI/openpass_coreFFI.modulemap "$HDR/module.modulemap"
cat "$HDR/module.modulemap"

echo "==> xcframework"
rm -rf "$OUT/OpenPassCoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$OUT/libopenpass_core.a" \
  -headers "$HDR" \
  -output "$OUT/OpenPassCoreFFI.xcframework"

echo "Done: $OUT/OpenPassCoreFFI.xcframework"
