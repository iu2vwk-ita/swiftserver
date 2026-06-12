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

# Log directory
LOG_DIR = "/opt/server-monitor/logs"
