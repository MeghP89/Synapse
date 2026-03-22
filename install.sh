#!/usr/bin/env bash
set -euo pipefail

REPO="MeghP89/Synapse"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/usr/local/share/synapse"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)        ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
  linux)  PLATFORM="linux-$ARCH" ;;
  darwin) PLATFORM="macos-$ARCH" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BUILD_FROM_SOURCE=0
TMP=""

LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
  | grep '"tag_name"' | cut -d'"' -f4 || true)

if [ -n "$LATEST" ]; then
  DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST/synapse-$PLATFORM"
  TMP=$(mktemp)
  echo "Downloading synapse $LATEST ($PLATFORM)..."
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP" 2>/dev/null; then
    echo "No pre-built binary for $PLATFORM, building from source..."
    rm -f "$TMP"
    BUILD_FROM_SOURCE=1
  fi
else
  echo "No releases found, building from source..."
  BUILD_FROM_SOURCE=1
fi

if [ "$BUILD_FROM_SOURCE" = "1" ]; then
  if ! command -v cargo &>/dev/null; then
    echo "Rust not found — installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT
  echo "Cloning repository..."
  git clone "https://github.com/$REPO.git" "$TMP_DIR/synapse"
  echo "Building (this may take a minute)..."
  cargo build --release --manifest-path "$TMP_DIR/synapse/Cargo.toml"
  TMP="$TMP_DIR/synapse/target/release/synapse"
fi

echo "Installing binary to $INSTALL_DIR/synapse..."
if [ -w "$INSTALL_DIR" ]; then
  cp "$TMP" "$INSTALL_DIR/synapse"
  chmod +x "$INSTALL_DIR/synapse"
else
  sudo cp "$TMP" "$INSTALL_DIR/synapse"
  sudo chmod +x "$INSTALL_DIR/synapse"
fi

echo "Installing service data to $DATA_DIR..."
if [ -w "$(dirname "$DATA_DIR")" ]; then
  mkdir -p "$DATA_DIR"
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/data/nmap-services" \
    -o "$DATA_DIR/nmap-services"
else
  sudo mkdir -p "$DATA_DIR"
  sudo curl -fsSL "https://raw.githubusercontent.com/$REPO/main/data/nmap-services" \
    -o "$DATA_DIR/nmap-services"
fi

echo ""
echo "synapse installed successfully."
echo "Usage: sudo synapse --help"
