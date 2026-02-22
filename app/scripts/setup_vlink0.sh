#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script only runs on Linux." >&2
  exit 2
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "ip command not found. Install iproute2." >&2
  exit 2
fi

DEV=vlink0
ADDR=172.19.0.1/30

sudo ip tuntap add dev ${DEV} mode tun || true
sudo ip addr add ${ADDR} dev ${DEV} || true
sudo ip link set dev ${DEV} up

echo "TUN device ${DEV} is up with ${ADDR}"
