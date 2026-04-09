#!/usr/bin/env bash
set -euo pipefail

cargo build

BIN="target/debug/synapse"
if command -v getcap >/dev/null 2>&1; then
  if ! getcap "$BIN" 2>/dev/null | grep -q "cap_net_raw"; then
    echo "Applying cap_net_raw to $BIN (requires sudo once)..."
    sudo setcap cap_net_raw+ep "$BIN"
  fi
else
  echo "Warning: getcap not found. Ensure $BIN has cap_net_raw or use sudo for raw scans."
fi

"$BIN" "$@"
