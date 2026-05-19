#!/bin/bash
# Build Debian/Ubuntu .deb package for ByteSweep
set -e

VERSION="1.0.0"
PACKAGE="bytesweep"
BUILD_DIR="/tmp/${PACKAGE}-deb"
DEB_FILE="${PACKAGE}_${VERSION}_all.deb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building ${PACKAGE} v${VERSION} .deb package..."

# Clean previous build
rm -rf "$BUILD_DIR"

# Create staging directory structure
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/opt/server-monitor/static"
mkdir -p "$BUILD_DIR/opt/server-monitor/logs"
mkdir -p "$BUILD_DIR/opt/server-monitor/venv"

# Copy DEBIAN control files
cp "$SCRIPT_DIR/debian/DEBIAN/control"    "$BUILD_DIR/DEBIAN/"
cp "$SCRIPT_DIR/debian/DEBIAN/postinst"   "$BUILD_DIR/DEBIAN/"
cp "$SCRIPT_DIR/debian/DEBIAN/postrm"     "$BUILD_DIR/DEBIAN/"
cp "$SCRIPT_DIR/debian/DEBIAN/conffiles"  "$BUILD_DIR/DEBIAN/"
chmod 755 "$BUILD_DIR/DEBIAN/postinst"
chmod 755 "$BUILD_DIR/DEBIAN/postrm"

# Copy application files
cp "$SCRIPT_DIR/server_monitor.py" "$BUILD_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/cleanup.py"        "$BUILD_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/auto_cleanup.py"   "$BUILD_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/config.py"         "$BUILD_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/requirements.txt"  "$BUILD_DIR/opt/server-monitor/"
cp -r "$SCRIPT_DIR/static/"*       "$BUILD_DIR/opt/server-monitor/static/"

# Set ownership to root
chown -R root:root "$BUILD_DIR"

# Build the .deb package
dpkg-deb --build "$BUILD_DIR" "$SCRIPT_DIR/$DEB_FILE"

# Clean up
rm -rf "$BUILD_DIR"

echo ""
echo "Package built: $DEB_FILE"
echo "Size: $(du -h "$SCRIPT_DIR/$DEB_FILE" | cut -f1)"
echo ""
echo "Install with: sudo dpkg -i $DEB_FILE"
echo "or:            sudo apt install ./$DEB_FILE"
