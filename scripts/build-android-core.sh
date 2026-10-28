#!/usr/bin/env bash
# Build the Rust core as Android .so libraries (arm64-v8a + x86_64) into jniLibs.
# Requires: rustup targets aarch64-linux-android x86_64-linux-android, Android NDK.
set -euo pipefail
cd "$(dirname "$0")/.."

ANDROID_HOME="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
NDK="$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
echo "Using NDK: $NDK"

rustup target add aarch64-linux-android x86_64-linux-android >/dev/null

echo "==> aarch64-linux-android -> arm64-v8a"
env CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android29-clang" \
    CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android29-clang" \
    AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar" \
  cargo build --manifest-path crates/openpass-core/Cargo.toml \
    --release --features uniffi --target aarch64-linux-android
mkdir -p apps/android/app/src/main/jniLibs/arm64-v8a
cp crates/openpass-core/target/aarch64-linux-android/release/libopenpass_core.so \
   apps/android/app/src/main/jniLibs/arm64-v8a/libopenpass_core.so

echo "==> x86_64-linux-android -> x86_64"
env CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android29-clang" \
    CC_x86_64_linux_android="$TOOLCHAIN/x86_64-linux-android29-clang" \
    AR_x86_64_linux_android="$TOOLCHAIN/llvm-ar" \
  cargo build --manifest-path crates/openpass-core/Cargo.toml \
    --release --features uniffi --target x86_64-linux-android
mkdir -p apps/android/app/src/main/jniLibs/x86_64
cp crates/openpass-core/target/x86_64-linux-android/release/libopenpass_core.so \
   apps/android/app/src/main/jniLibs/x86_64/libopenpass_core.so

echo "Done. Rebuild the APK: (cd apps/android && ./gradlew assembleDebug)"
