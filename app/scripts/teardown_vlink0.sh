#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script only runs on Linux." >&2
  exit 2
fi

DEV=vlink0

sudo ip link set dev ${DEV} down || true
sudo ip tuntap del dev ${DEV} mode tun || true

echo "TUN device ${DEV} removed"
