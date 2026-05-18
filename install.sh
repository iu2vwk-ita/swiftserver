#!/bin/bash
# ByteSweep - Server Monitor & Cleanup Agent
# One-liner: curl -sSL https://raw.githubusercontent.com/adivor/bytesweep/main/install.sh | bash
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
        --help) echo "Usage: $0 [--with-auto-cleanup]"; exit 0 ;;
    esac
done

echo "╔══════════════════════════════════════════════════════╗"
echo "║           ByteSweep Installer v${VERSION}               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  This script requires root privileges."
   echo "   Run with: sudo $0"
   exit 1
fi

# Detect system
if command -v systemctl &> /dev/null; then
    SYSTEMD_AVAILABLE=true
else
    SYSTEMD_AVAILABLE=false
fi

echo "[1/5] Checking dependencies..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "❌ Python3 not found. Installing..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-pip
    elif command -v apk &> /dev/null; then
        apk add --no-cache python3 py3-pip
    fi
    PYTHON_CMD="python3"
fi

echo "[2/5] Creating installation directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[3/5] Installing Python dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

echo "[4/5] Installing application files..."
# Copy application files
cp "$SCRIPT_DIR/server_monitor.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/config.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/cleanup.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/auto_cleanup.py" "$INSTALL_DIR/"

# Create web static directory
mkdir -p "$INSTALL_DIR/static"
cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/" 2>/dev/null || true

# Create logs directory
mkdir -p "$INSTALL_DIR/logs"

echo "[5/5] Setting up service..."

if [ "$SYSTEMD_AVAILABLE" = true ]; then
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
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
EOF

    # Auto-cleanup timer (hourly)
    if [ "$AUTO_CLEANUP" = true ]; then
        cat > /etc/systemd/system/${SERVICE_NAME}-cleanup.service << EOF
[Unit]
Description=ByteSweep Auto-Cleanup
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/auto_cleanup.py
EOF

        cat > /etc/systemd/system/${SERVICE_NAME}-cleanup.timer << EOF
[Unit]
Description=ByteSweep Auto-Cleanup Timer (hourly)

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}

    if [ "$AUTO_CLEANUP" = true ]; then
        systemctl enable ${SERVICE_NAME}-cleanup.timer
        systemctl start ${SERVICE_NAME}-cleanup.timer
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║            ✅ INSTALLATION COMPLETE             ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""
    echo "🌐 Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "Commands:"
    echo "  sudo systemctl status ${SERVICE_NAME}     # Check status"
    echo "  sudo systemctl restart ${SERVICE_NAME}     # Restart"
    echo "  sudo systemctl stop ${SERVICE_NAME}        # Stop"
    echo "  sudo journalctl -u ${SERVICE_NAME} -f     # View logs"
    if [ "$AUTO_CLEANUP" = true ]; then
        echo ""
        echo "  Auto-cleanup: ENABLED (runs hourly when disk > 90%)"
        echo "  sudo systemctl status ${SERVICE_NAME}-cleanup.timer"
        echo "  tail -f ${INSTALL_DIR}/logs/cleanup.log"
    fi
    echo ""
else
    # Create init.d script
    cat > /etc/init.d/${SERVICE_NAME} << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          ${SERVICE_NAME}
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       ByteSweep Server Monitor
### END INIT INFO

case "\$1" in
    start)
        cd "$INSTALL_DIR"
        nohup $INSTALL_DIR/venv/bin/python $INSTALL_DIR/server_monitor.py > $INSTALL_DIR/logs/service.log 2>&1 &
        echo "ByteSweep started"
        ;;
    stop)
        pkill -f server_monitor.py
        echo "ByteSweep stopped"
        ;;
    restart)
        pkill -f server_monitor.py
        sleep 1
        cd "$INSTALL_DIR"
        nohup $INSTALL_DIR/venv/bin/python $INSTALL_DIR/server_monitor.py > $INSTALL_DIR/logs/service.log 2>&1 &
        echo "ByteSweep restarted"
        ;;
esac
exit 0
EOF

    chmod +x /etc/init.d/${SERVICE_NAME}
    update-rc.d ${SERVICE_NAME} defaults

    # Start now
    /etc/init.d/${SERVICE_NAME} start

    # Auto-cleanup via cron (non-systemd)
    if [ "$AUTO_CLEANUP" = true ]; then
        (crontab -l 2>/dev/null; echo "0 * * * * $INSTALL_DIR/venv/bin/python $INSTALL_DIR/auto_cleanup.py") | crontab -
        echo "  Auto-cleanup: ENABLED via cron (hourly)"
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║            ✅ INSTALLATION COMPLETE             ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""
    echo "🌐 Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "Commands:"
    echo "  sudo /etc/init.d/${SERVICE_NAME} status     # Check status"
    echo "  sudo /etc/init.d/${SERVICE_NAME} restart    # Restart"
    echo "  sudo /etc/init.d/${SERVICE_NAME} stop       # Stop"
fi

echo "📊 ByteSweep is running!"