SERVER_PORT = 5000
SERVER_HOST = "0.0.0.0"
UPDATE_INTERVAL = 2
ENABLE_TEMPS = True
LOG_LEVEL = "INFO"

# --- Access Logging ---
ACCESS_LOG = True
ACCESS_LOG_FILE = "/opt/server-monitor/logs/access.log"

# --- Authentication (optional) ---
# Set to None or empty string to disable password protection
PANEL_PASSWORD = None
# Session token expiry in hours
SESSION_EXPIRY_HOURS = 4

# --- Security Scanning ---
# Directories to scan for viruses (ClamAV required)
VIRUS_SCAN_PATHS = ["/tmp", "/var/tmp", "/home"]
# Maximum scan time in seconds per path
VIRUS_SCAN_TIMEOUT = 300

# Mining detection CPU threshold (percent) to flag suspicious processes
MINING_CPU_THRESHOLD = 50
# Known mining process name patterns
MINING_PATTERNS = ["xmrig", "cpuminer", "minergate", "t-rex", "phoenixminer",
                   "lolminer", "nbminer", "gminer", "ethminer", "claymore",
                   "teamredminer", "cryptominer", "xmr-stak", "sgminer",
                   "cgminer", "bfgminer", "minerd", "ccminer", "cpuminer-opt"]

# Port scanning: how recent is "recent" in seconds
RECENT_PORT_THRESHOLD = 300

# --- Scheduled Scanning ---
# Run forensic scan every N seconds (0 = disabled)
SCHEDULED_SCAN_INTERVAL = 0
# Webhook URL for alerts (Telegram bot or generic webhook)
# Telegram format: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
ALERT_WEBHOOK_URL = None

# --- Auto-Kill Miners ---
# Automatically kill processes identified as known crypto miners
AUTO_KILL_MINERS = False

# --- Integrity Monitor ---
# Files to monitor for changes (SHA256 baseline check)
INTEGRITY_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab",
    "/bin/ls", "/bin/ps", "/usr/bin/ssh", "/usr/bin/systemctl",
]

# Log directory
LOG_DIR = "/opt/server-monitor/logs"
