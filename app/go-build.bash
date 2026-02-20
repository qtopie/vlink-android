#!/bin/bash
set -e

# Setup NDK
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
    if [[ -d "${ANDROID_HOME}/ndk-bundle" ]]; then
        ANDROID_NDK_HOME="${ANDROID_HOME}/ndk-bundle"
    elif [[ -d "${ANDROID_HOME}/ndk" ]]; then
        LATEST_NDK=$(ls -1 "${ANDROID_HOME}/ndk" 2>/dev/null | sort -V | tail -n1)
        if [[ -n "$LATEST_NDK" ]]; then
            ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/$LATEST_NDK"
        fi
    fi
fi

if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "Error: ANDROID_NDK_HOME not found."
    exit 1
fi

TOOLCHAIN="$(find ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/* -maxdepth 1 -type d -print -quit)/bin"

# Build configuration
ABI="arm64-v8a"
GO_ARCH="arm64"
CLANG_ARCH="aarch64-linux-android"
MIN_API="${1:-21}"

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Note: output to jniLibs so Gradle picks it up automatically if configured
OUT_DIR="$ROOT/src/main/jniLibs/${ABI}"
mkdir -p "$OUT_DIR"

echo "Building libvlink.so (JNI) for ${ABI} (API ${MIN_API})..."

export CGO_ENABLED=1
export GOOS=android
export GOARCH=${GO_ARCH}
export GOARM64=v8.0
export CC="${TOOLCHAIN}/${CLANG_ARCH}${MIN_API}-clang"

# Check if CC exists
if [[ ! -x "$CC" ]]; then
    CC="${TOOLCHAIN}/${CLANG_ARCH}-clang"
    if [[ ! -x "$CC" ]]; then
        echo "Error: Compiler not found at $CC"
        exit 1
    fi
fi

cd "$ROOT/src/main/golang"

# Build as c-shared library
go build -v -buildmode=c-shared -ldflags="-s -w -extldflags=-llog" -trimpath -o "${OUT_DIR}/libvlink.so" .

echo "Build complete: ${OUT_DIR}/libvlink.so"
