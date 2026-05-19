#!/bin/bash
# ByteSweep - Server Monitor & Cleanup Agent
# One-liner: curl -sSL https://raw.githubusercontent.com/iu2vwk-ita/swiftserver/main/install.sh | bash
# With auto-cleanup: curl ... | bash -s -- --with-auto-cleanup

set -e

VERSION="1.0.0"
INSTALL_DIR="/opt/server-monitor"
SERVICE_NAME="bytesweep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_CLEANUP=false

# Parse flags
for arg in "$@"; do
    case $arg in
        --with-auto-cleanup) AUTO_CLEANUP=true ;;
        --version) echo "ByteSweep v${VERSION}"; exit 0 ;;
        --help)
            echo "ByteSweep v${VERSION} - Linux Server Monitor & Cleanup Agent"
            echo ""
            echo "Usage: $0 [--with-auto-cleanup]"
            echo ""
            echo "Options:"
            echo "  --with-auto-cleanup   Enable hourly auto-cleanup timer"
            echo "  --version             Show version"
            echo "  --help                Show this help"
            echo ""
            echo "Available package formats:"
            echo "  Debian/Ubuntu:  sudo dpkg -i bytesweep_*.deb"
            echo "  Fedora/RHEL:    sudo rpm -i bytesweep-*.rpm"
            echo "  Arch Linux:     makepkg -si (use PKGBUILD)"
            echo "  AppImage:       chmod +x ByteSweep-*.AppImage && ./ByteSweep-*.AppImage"
            echo "  Any Linux:      sudo ./install.sh"
            exit 0
            ;;
    esac
done

# ── Distribution detection ──

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)

echo "╔══════════════════════════════════════════════════════╗"
echo "║         ByteSweep Installer v${VERSION}                ║"
echo "║         $(printf '%-40s' "Detected: ${DISTRO}") ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Prefer distro-native packages when available ──

check_and_offer_package() {
    case "$DISTRO" in
        debian|ubuntu|linuxmint|pop|elementary|kali|raspbian|zorin)
            if [ -f "$SCRIPT_DIR/bytesweep_${VERSION}_all.deb" ]; then
                echo "   Debian package found. For clean install/removal, use:"
                echo "   sudo dpkg -i bytesweep_${VERSION}_all.deb"
                echo ""
                echo "   To build from source: ./build-deb.sh"
                echo ""
            fi
            ;;
        fedora|rhel|centos|rocky|almalinux|ol|sangoma)
            if [ -f "$SCRIPT_DIR/bytesweep-${VERSION}"*.rpm ]; then
                echo "   RPM package found. For clean install/removal, use:"
                echo "   sudo rpm -i bytesweep-${VERSION}*.rpm"
                echo ""
                echo "   To build from source: ./build-rpm.sh"
                echo ""
            fi
            ;;
        arch|manjaro|endeavouros|garuda)
            if [ -f "$SCRIPT_DIR/PKGBUILD" ]; then
                echo "   Arch PKGBUILD found. For clean install/removal, use:"
                echo "   makepkg -si"
                echo ""
            fi
            ;;
    esac
}

check_and_offer_package

echo "Proceeding with direct script install..."
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script requires root privileges."
   echo "Run with: sudo $0"
   exit 1
fi

# Detect system
if command -v systemctl &> /dev/null; then
    SYSTEMD_AVAILABLE=true
else
    SYSTEMD_AVAILABLE=false
fi

echo "[1/6] Checking dependencies..."
MISSING_DEPS=""

if ! command -v python3 &> /dev/null; then
    MISSING_DEPS="$MISSING_DEPS python3"
fi
if ! python3 -c "import venv" 2>/dev/null; then
    MISSING_DEPS="$MISSING_DEPS python3-venv"
fi

if [ -n "$MISSING_DEPS" ]; then
    echo "   Installing:${MISSING_DEPS}..."
    case "$DISTRO" in
        debian|ubuntu|linuxmint|pop|elementary|kali|raspbian|zorin)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip python3-venv
            ;;
        fedora|rhel|centos|rocky|almalinux|ol)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip
            else
                yum install -y python3 python3-pip
            fi
            ;;
        arch|manjaro|endeavouros|garuda)
            pacman -S --noconfirm python python-pip
            ;;
        alpine)
            apk add --no-cache python3 py3-pip
            ;;
        opensuse*|sles)
            zypper install -y python3 python3-pip
            ;;
        *)
            echo "   Unknown distribution. Please install Python 3.8+ manually."
            exit 1
            ;;
    esac
fi

echo "[2/6] Creating installation directory..."
mkdir -p "$INSTALL_DIR"

echo "[3/6] Installing Python dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

echo "[4/6] Installing application files..."
cp "$SCRIPT_DIR/server_monitor.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/config.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/cleanup.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/auto_cleanup.py" "$INSTALL_DIR/"

mkdir -p "$INSTALL_DIR/static"
cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/" 2>/dev/null || true

mkdir -p "$INSTALL_DIR/logs"

echo "[5/6] Setting up service..."
setup_systemd_service() {
    cat > /etc/systemd/system/${SERVICE_NAME}.service << UNIT
[Unit]
Description=ByteSweep - Server Monitor & Auto-Cleanup Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/server_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

    cat > /etc/systemd/system/${SERVICE_NAME}-cleanup.service << UNIT
[Unit]
Description=ByteSweep Auto-Cleanup
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/auto_cleanup.py
UNIT

    cat > /etc/systemd/system/${SERVICE_NAME}-cleanup.timer << UNIT
[Unit]
Description=ByteSweep Auto-Cleanup Timer (hourly)

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}

    systemctl enable ${SERVICE_NAME}-cleanup.timer
    systemctl start ${SERVICE_NAME}-cleanup.timer
}

setup_initd_service() {
    cat > /etc/init.d/${SERVICE_NAME} << 'INIT'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          bytesweep
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       ByteSweep Server Monitor & Cleanup
### END INIT INFO

case "$1" in
    start)
        cd /opt/server-monitor
        nohup /opt/server-monitor/venv/bin/python /opt/server-monitor/server_monitor.py > /opt/server-monitor/logs/service.log 2>&1 &
        echo "ByteSweep started"
        ;;
    stop)
        pkill -f server_monitor.py
        echo "ByteSweep stopped"
        ;;
    restart)
        pkill -f server_monitor.py
        sleep 1
        cd /opt/server-monitor
        nohup /opt/server-monitor/venv/bin/python /opt/server-monitor/server_monitor.py > /opt/server-monitor/logs/service.log 2>&1 &
        echo "ByteSweep restarted"
        ;;
    status)
        if pgrep -f server_monitor.py > /dev/null; then
            echo "ByteSweep is running"
        else
            echo "ByteSweep is stopped"
        fi
        ;;
esac
exit 0
INIT

    chmod +x /etc/init.d/${SERVICE_NAME}

    # Enable at boot (works on most init systems)
    if command -v update-rc.d &> /dev/null; then
        update-rc.d ${SERVICE_NAME} defaults
    elif command -v chkconfig &> /dev/null; then
        chkconfig --add ${SERVICE_NAME}
    elif command -v rc-update &> /dev/null; then
        rc-update add ${SERVICE_NAME} default
    fi

    /etc/init.d/${SERVICE_NAME} start
}

if [ "$SYSTEMD_AVAILABLE" = true ]; then
    setup_systemd_service
else
    setup_initd_service

    if [ "$AUTO_CLEANUP" = true ]; then
        (crontab -l 2>/dev/null; echo "0 * * * * $INSTALL_DIR/venv/bin/python $INSTALL_DIR/auto_cleanup.py") | crontab -
    fi
fi

echo "[6/6] Verifying installation..."
sleep 2

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$IP" ]; then
    IP="YOUR_SERVER_IP"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║            INSTALLATION COMPLETE                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo " Dashboard:     http://${IP}:5000"
echo " Install dir:   ${INSTALL_DIR}"
echo " Service:       ${SERVICE_NAME}"
echo ""
echo " Commands:"
echo "   sudo systemctl status ${SERVICE_NAME}     # Check status"
echo "   sudo systemctl restart ${SERVICE_NAME}    # Restart"
echo "   sudo systemctl stop ${SERVICE_NAME}       # Stop"
echo "   sudo journalctl -u ${SERVICE_NAME} -f     # View logs"

if [ "$SYSTEMD_AVAILABLE" = true ]; then
    echo ""
    echo " Auto-cleanup:  ENABLED (runs hourly)"
    echo "   sudo systemctl status ${SERVICE_NAME}-cleanup.timer"
    echo "   tail -f ${INSTALL_DIR}/logs/cleanup.log"
else
    echo ""
    echo " Service:       sudo /etc/init.d/${SERVICE_NAME} {start|stop|restart|status}"
fi

echo ""
echo " To uninstall later:"
echo "   sudo systemctl stop ${SERVICE_NAME} && sudo systemctl disable ${SERVICE_NAME}"
echo "   sudo rm -rf ${INSTALL_DIR} /etc/systemd/system/${SERVICE_NAME}*"
echo ""
echo " ByteSweep is running"
