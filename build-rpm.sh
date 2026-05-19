#!/bin/bash
# Build RPM package for ByteSweep
# Requires: rpm-build, rpmdevtools
set -e

VERSION="1.0.0"
PACKAGE="bytesweep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RPMBUILD_DIR="$HOME/rpmbuild"

echo "Building ${PACKAGE} v${VERSION} RPM package..."

# Check for rpmbuild
if ! command -v rpmbuild &> /dev/null; then
    echo "Error: rpmbuild not found. Install with:"
    echo "  sudo apt install rpm         (Debian/Ubuntu)"
    echo "  sudo dnf install rpm-build   (Fedora/RHEL)"
    exit 1
fi

# Set up rpmbuild directories
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy spec file
cp "$SCRIPT_DIR/rpm/bytesweep.spec" "$RPMBUILD_DIR/SPECS/"

# Create source directory with all files for the build
BUILD_SRC="$RPMBUILD_DIR/BUILD/${PACKAGE}-${VERSION}"
rm -rf "$BUILD_SRC"
mkdir -p "$BUILD_SRC/static"
cp "$SCRIPT_DIR/server_monitor.py" "$BUILD_SRC/"
cp "$SCRIPT_DIR/cleanup.py"        "$BUILD_SRC/"
cp "$SCRIPT_DIR/auto_cleanup.py"   "$BUILD_SRC/"
cp "$SCRIPT_DIR/config.py"         "$BUILD_SRC/"
cp "$SCRIPT_DIR/requirements.txt"  "$BUILD_SRC/"
cp -r "$SCRIPT_DIR/static/"*       "$BUILD_SRC/static/"

# Build RPM
rpmbuild -bb \
    --define "_topdir $RPMBUILD_DIR" \
    --define "buildsubdir ${PACKAGE}-${VERSION}" \
    "$RPMBUILD_DIR/SPECS/bytesweep.spec"

# Find and copy the RPM
RPM_FILE=$(find "$RPMBUILD_DIR/RPMS" -name "${PACKAGE}-${VERSION}*.rpm" | head -1)
if [ -n "$RPM_FILE" ]; then
    cp "$RPM_FILE" "$SCRIPT_DIR/"
    RPM_NAME=$(basename "$RPM_FILE")
    echo ""
    echo "Package built: $RPM_NAME"
    echo "Size: $(du -h "$SCRIPT_DIR/$RPM_NAME" | cut -f1)"
    echo ""
    echo "Install with: sudo rpm -i $RPM_NAME"
    echo "or:            sudo dnf install ./$RPM_NAME"
fi
