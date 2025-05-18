#!/bin/bash
# install_netscan.sh - Build and install the netscan binary system-wide or to ~/bin

set -e

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${GREEN}==> Netscan Installer${NC}"

# Check for cargo
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${RED}Cargo (Rust) is not installed.${NC}"
    echo -e "${YELLOW}Install Rust from https://rustup.rs/ and try again.${NC}"
    exit 1
fi

# Build the release binary
echo -e "${GREEN}==> Building netscan in release mode...${NC}"
cargo build --release

BIN_PATH="target/release/netscan"
if [ ! -f "$BIN_PATH" ]; then
    echo -e "${RED}Build failed or binary not found at $BIN_PATH${NC}"
    exit 1
fi

# Ask user for install location
echo -e "${YELLOW}Install netscan for:${NC}"
echo "  1) All users (/usr/local/bin, requires sudo)"
echo "  2) Current user only (\$HOME/bin)"
read -rp "Choose [1/2]: " choice

if [[ "$choice" == "1" ]]; then
    INSTALL_DIR="/usr/local/bin"
    if [ ! -w "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}Sudo required to install to $INSTALL_DIR${NC}"
        sudo cp "$BIN_PATH" "$INSTALL_DIR/netscan"
        sudo chmod +x "$INSTALL_DIR/netscan"
    else
        cp "$BIN_PATH" "$INSTALL_DIR/netscan"
        chmod +x "$INSTALL_DIR/netscan"
    fi
elif [[ "$choice" == "2" ]]; then
    INSTALL_DIR="$HOME/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$BIN_PATH" "$INSTALL_DIR/netscan"
    chmod +x "$INSTALL_DIR/netscan"
    # Add to PATH if not present
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        SHELL_PROFILE=""
        if [ -n "$BASH_VERSION" ]; then
            SHELL_PROFILE="$HOME/.bashrc"
        elif [ -n "$ZSH_VERSION" ]; then
            SHELL_PROFILE="$HOME/.zshrc"
        else
            SHELL_PROFILE="$HOME/.profile"
        fi
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_PROFILE"
        echo -e "${YELLOW}Added $INSTALL_DIR to PATH in $SHELL_PROFILE${NC}"
        export PATH="$INSTALL_DIR:$PATH"
    fi
else
    echo -e "${RED}Invalid choice. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}==> netscan installed to $INSTALL_DIR${NC}"

# Verify install
if command -v netscan >/dev/null 2>&1; then
    echo -e "${GREEN}==> netscan version:${NC}"
    netscan --version || echo -e "${YELLOW}(Could not get version info)${NC}"
    echo -e "${GREEN}==> Run:${NC} netscan --help"
else
    echo -e "${YELLOW}netscan installed, but not found in PATH for this session.${NC}"
    echo "You may need to restart your terminal or run:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi