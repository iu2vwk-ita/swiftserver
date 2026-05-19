#!/bin/bash
# Build AppImage for ByteSweep
# Creates a self-contained, portable AppImage for any Linux distribution
set -e

VERSION="1.0.0"
APP="ByteSweep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="/tmp/${APP}-appimage"
APP_DIR="$BUILD_DIR/${APP}.AppDir"

echo "Building ${APP} v${VERSION} AppImage..."

# Check for required tools
if ! command -v appimagetool &> /dev/null; then
    echo "appimagetool not found. Downloading..."
    ARCH=$(uname -m)
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage" -O /tmp/appimagetool
    chmod +x /tmp/appimagetool
    APPIMAGETOOL=/tmp/appimagetool
else
    APPIMAGETOOL=appimagetool
fi

# Clean previous build
rm -rf "$BUILD_DIR"

# Create AppDir structure
mkdir -p "$APP_DIR/opt/server-monitor/static"
mkdir -p "$APP_DIR/opt/server-monitor/logs"
mkdir -p "$APP_DIR/usr/share/applications"
mkdir -p "$APP_DIR/usr/share/icons/hicolor/256x256/apps"

# Copy application files
cp "$SCRIPT_DIR/server_monitor.py" "$APP_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/cleanup.py"        "$APP_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/auto_cleanup.py"   "$APP_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/config.py"         "$APP_DIR/opt/server-monitor/"
cp "$SCRIPT_DIR/requirements.txt"  "$APP_DIR/opt/server-monitor/"
cp -r "$SCRIPT_DIR/static/"*       "$APP_DIR/opt/server-monitor/static/"

# Create Python virtualenv inside AppDir
echo "Setting up Python environment..."
python3 -m venv "$APP_DIR/opt/server-monitor/venv"
"$APP_DIR/opt/server-monitor/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

# Create launcher script
cat > "$APP_DIR/AppRun" << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/opt/server-monitor/venv/bin/python" "$HERE/opt/server-monitor/server_monitor.py" "$@"
EOF
chmod +x "$APP_DIR/AppRun"

# Create desktop entry
cat > "$APP_DIR/usr/share/applications/bytesweep.desktop" << EOF
[Desktop Entry]
Name=ByteSweep
Comment=Linux Server Monitoring Dashboard
Exec=AppRun
Icon=bytesweep
Terminal=true
Type=Application
Categories=System;Monitor;
EOF

# Create icon placeholder (generate a simple SVG)
cat > "$APP_DIR/usr/share/icons/hicolor/256x256/apps/bytesweep.png" << 'EOF'
# Placeholder icon - replace with actual icon file
EOF

# Copy icon for AppImage
cp "$APP_DIR/usr/share/icons/hicolor/256x256/apps/bytesweep.png" "$APP_DIR/bytesweep.png" 2>/dev/null || true

# Build AppImage
ARCH=$(uname -m)
"$APPIMAGETOOL" "$APP_DIR" "$SCRIPT_DIR/ByteSweep-${VERSION}-${ARCH}.AppImage"

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "AppImage built: ByteSweep-${VERSION}-${ARCH}.AppImage"
echo "Size: $(du -h "$SCRIPT_DIR/ByteSweep-${VERSION}-${ARCH}.AppImage" | cut -f1)"
echo ""
echo "Usage:"
echo "  chmod +x ByteSweep-${VERSION}-${ARCH}.AppImage"
echo "  ./ByteSweep-${VERSION}-${ARCH}.AppImage"
echo ""
echo "Dashboard will be available at http://0.0.0.0:5000"
