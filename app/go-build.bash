#!/bin/bash
set -euo pipefail

# Usage: ./go-build.bash [aar|so] [MIN_API]
# Default: build AAR via gomobile (preferred). Use 'so' to build c-shared (.so) like before.

export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/29.0.14206865

MODE="${1:-aar}"
MIN_API="${2:-33}"

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$ROOT" || exit 1

case "$MODE" in
  aar)
    echo "Building Android AAR via gomobile (target=android)..."

    # Ensure gomobile is installed
    # If gomobile isn't in PATH, try common locations (GOPATH/bin, GOBIN, HOME/go/bin, workspace go/bin)
    if ! command -v gomobile >/dev/null 2>&1; then
        echo "gomobile not found in PATH — probing common Go bin locations..."
        if command -v go >/dev/null 2>&1; then
            GOPATH_DIR=$(go env GOPATH 2>/dev/null || true)
            GOBIN_DIR=$(go env GOBIN 2>/dev/null || true)
        else
            GOPATH_DIR=""
            GOBIN_DIR=""
        fi

        CANDIDATES=("${GOBIN_DIR}" "${GOPATH_DIR}/bin" "$HOME/go/bin" "$HOME/workspace/go/bin")
        for d in "${CANDIDATES[@]}"; do
            if [[ -n "$d" && -x "$d/gomobile" ]]; then
                export PATH="$d:$PATH"
                echo "Found gomobile at $d/gomobile, added to PATH"
                break
            fi
        done

        # If still not found, attempt to install
        if ! command -v gomobile >/dev/null 2>&1; then
            echo "gomobile not found — installing golang.org/x/mobile/cmd/gomobile..."
            if command -v go >/dev/null 2>&1; then
                go install golang.org/x/mobile/cmd/gomobile@latest
                # newly installed binary may be in GOPATH/bin or GOBIN; try to find and add it
                if [[ -n "${GOBIN_DIR}" && -x "${GOBIN_DIR}/gomobile" ]]; then
                    export PATH="${GOBIN_DIR}:$PATH"
                elif [[ -n "${GOPATH_DIR}" && -x "${GOPATH_DIR}/bin/gomobile" ]]; then
                    export PATH="${GOPATH_DIR}/bin:$PATH"
                elif [[ -x "$HOME/go/bin/gomobile" ]]; then
                    export PATH="$HOME/go/bin:$PATH"
                fi
            else
                echo "Error: go tool not found in PATH"
                exit 1
            fi
        fi
    fi

    # Run gomobile init if needed (ensure gobind is present and gomobile is initialized)
    if ! command -v gobind >/dev/null 2>&1 || ! gomobile version >/dev/null 2>&1; then
        echo "Initializing gomobile (this may take a while)..."
        gomobile init
    fi

    OUT_DIR="$ROOT/src/main/libs"
    mkdir -p "$OUT_DIR"

    pushd "$ROOT/src/main/golang" >/dev/null
    echo "Running: gomobile bind -target=android -androidapi 33 -o ${OUT_DIR}/vlink.aar github.com/qtopie/vlink/libvlink (GO111MODULE=on, GOFLAGS=-mod=mod)"
    export GO111MODULE=on
    export GOFLAGS="-mod=mod"
    gomobile bind -target=android -androidapi 33 -o "${OUT_DIR}/vlink.aar" github.com/qtopie/vlink/libvlink
    popd >/dev/null

    echo "Build complete: ${OUT_DIR}/vlink.aar"
    ;;
  so)
    echo "Building libvlink.so (c-shared) for arm64-v8a (API ${MIN_API})..."

    # Setup NDK
    if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
        if [[ -d "${ANDROID_HOME:-}/ndk-bundle" ]]; then
            ANDROID_NDK_HOME="${ANDROID_HOME}/ndk-bundle"
        elif [[ -d "${ANDROID_HOME:-}/ndk" ]]; then
            LATEST_NDK=$(ls -1 "${ANDROID_HOME}/ndk" 2>/dev/null | sort -V | tail -n1)
            if [[ -n "$LATEST_NDK" ]]; then
                ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/$LATEST_NDK"
            fi
        fi
    fi

    if [[ ! -d "${ANDROID_NDK_HOME:-}" ]]; then
        echo "Error: ANDROID_NDK_HOME not found."
        exit 1
    fi

    TOOLCHAIN="$(find ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/* -maxdepth 1 -type d -print -quit)/bin"

    # Build configuration
    ABI="arm64-v8a"
    GO_ARCH="arm64"
    CLANG_ARCH="aarch64-linux-android"

    OUT_DIR="$ROOT/src/main/jniLibs/${ABI}"
    mkdir -p "$OUT_DIR"

    export CGO_ENABLED=1
    export GOOS=android
    export GOARCH=${GO_ARCH}
    export GOARM64=v8.0
    export CC="${TOOLCHAIN}/${CLANG_ARCH}${MIN_API}-clang"

    if [[ ! -x "$CC" ]]; then
        CC="${TOOLCHAIN}/${CLANG_ARCH}-clang"
        if [[ ! -x "$CC" ]]; then
            echo "Error: Compiler not found at $CC"
            exit 1
        fi
    fi

    pushd "$ROOT/src/main/golang" >/dev/null
    go build -v -buildmode=c-shared -ldflags="-s -w -extldflags=-llog" -trimpath -o "${OUT_DIR}/libvlink.so" .
    popd >/dev/null

    echo "Build complete: ${OUT_DIR}/libvlink.so"
    ;;
  *)
    echo "Unknown build mode: $MODE"
    echo "Usage: $0 [aar|so] [MIN_API]"
    exit 2
    ;;
esac
