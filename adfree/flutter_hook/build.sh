#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$DIR/.."
NDK="${ANDROID_NDK_HOME:-/Users/nguyenduy/Library/Android/sdk/ndk/27.1.12297006}"
CMAKE="${CMAKE_BIN:-/Users/nguyenduy/Library/Android/sdk/cmake/3.22.1/bin/cmake}"

build_abi() {
  ABI=$1
  echo "==> Building libflutter_hook.so for $ABI..."
  "$CMAKE" -B "$DIR/build_$ABI" -S "$DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM=android-24 \
    -DCMAKE_BUILD_TYPE=Release
  "$CMAKE" --build "$DIR/build_$ABI"
  "$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip" --strip-unneeded "$DIR/build_$ABI/libflutter_hook.so"
  mkdir -p "$ROOT/prebuilt/$ABI"
  cp "$DIR/build_$ABI/libflutter_hook.so" "$ROOT/prebuilt/$ABI/"
  echo "==> Done $ABI: $(ls -lh "$ROOT/prebuilt/$ABI/libflutter_hook.so")"
}

build_abi arm64-v8a
build_abi armeabi-v7a
