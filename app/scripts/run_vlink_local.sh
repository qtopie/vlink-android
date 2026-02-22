#!/usr/bin/env bash
set -euo pipefail

# Run the local linux test runner for TunInboundHandler.
# Usage: sudo ./run_vlink_local.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script only runs on Linux." >&2
  exit 2
fi

# Ensure TUN device exists
if ! ip link show vlink0 >/dev/null 2>&1; then
  echo "TUN device vlink0 not found. Run setup_vlink0.sh or run this script with sudo to auto-create."
  echo "Try: sudo ./setup_vlink0.sh"
  exit 1
fi

# Run from the go module directory
pushd "$(dirname "$0")/../src/main/golang" >/dev/null

# Use sudo to ensure access to /dev/net/tun
sudo go run ./cmd/local

popd >/dev/null
