#!/bin/bash
# Build Arch Linux package for ByteSweep
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="/tmp/bytesweep-arch"

echo "Building ByteSweep Arch Linux package..."

# Create build directory with source files
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cp "$SCRIPT_DIR/server_monitor.py" "$BUILD_DIR/"
cp "$SCRIPT_DIR/cleanup.py"        "$BUILD_DIR/"
cp "$SCRIPT_DIR/auto_cleanup.py"   "$BUILD_DIR/"
cp "$SCRIPT_DIR/config.py"         "$BUILD_DIR/"
cp "$SCRIPT_DIR/requirements.txt"  "$BUILD_DIR/"
mkdir -p "$BUILD_DIR/static"
cp "$SCRIPT_DIR/static/index.html" "$BUILD_DIR/static/"

cp "$SCRIPT_DIR/PKGBUILD"          "$BUILD_DIR/"
cp "$SCRIPT_DIR/bytesweep.install" "$BUILD_DIR/"

# Build the package
cd "$BUILD_DIR"
makepkg -si --noconfirm

PACKAGE_FILE=$(ls bytesweep-*.pkg.tar.zst 2>/dev/null)
if [ -n "$PACKAGE_FILE" ]; then
    cp "$PACKAGE_FILE" "$SCRIPT_DIR/"
    echo ""
    echo "Package built: $PACKAGE_FILE"
    echo "Size: $(du -h "$SCRIPT_DIR/$PACKAGE_FILE" | cut -f1)"
    echo ""
    echo "Install with: sudo pacman -U $PACKAGE_FILE"
fi

rm -rf "$BUILD_DIR"
