#!/bin/bash
# install_netscan.sh - Install the netscan binary system-wide or to ~/bin
# Usage: ./install_netscan.sh
# Builds the Rust project and copies the binary to /usr/local/bin or ~/bin

set -e

# Build the release binary
echo "Building netscan in release mode..."
cargo build --release

BIN_PATH="target/release/netscan"

if [ ! -f "$BIN_PATH" ]; then
    echo "Build failed or binary not found at $BIN_PATH"
    exit 1
fi

# Choose install location
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo "No write permission to $INSTALL_DIR, falling back to ~/bin"
    INSTALL_DIR="$HOME/bin"
    mkdir -p "$INSTALL_DIR"
    export PATH="$INSTALL_DIR:$PATH"
    echo "Added $INSTALL_DIR to PATH for this session."
fi

echo "Copying $BIN_PATH to $INSTALL_DIR/"
cp "$BIN_PATH" "$INSTALL_DIR/netscan"
chmod +x "$INSTALL_DIR/netscan"

echo "netscan installed to $INSTALL_DIR"
echo "You can now run: netscan --help"