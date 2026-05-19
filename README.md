# ByteSweep (SwiftServer)

A lightweight, real-time Linux server monitoring dashboard with integrated disk cleanup utilities -- perfect for purging heavy AI-generated temporary files and cache. Built with Flask and vanilla JavaScript for zero-dependency deployment on remote or headless machines.

## Features

- **Real-time Metrics** -- Live CPU, memory, disk, and network charts (Chart.js)
- **System Overview** -- Uptime, load average, CPU core count, temperature sensors
- **Top Processes** -- Auto-updating table of the most CPU-intensive processes
- **Network Details** -- Per-interface IP and MAC address discovery
- **Disk Visualization** -- Partition usage with color-coded progress bars
- **One-Click Cleanup** -- Web UI to run maintenance cleaners (APT, logs, Docker, caches)
- **Auto-Cleanup Agent** -- Background timer that cleans automatically when disk exceeds 90%
- **Responsive Dark UI** -- Works on desktop, tablet, and mobile

## Screenshots

<img width="1181" height="819" alt="Screenshot 2026-05-19 014518" src="https://github.com/user-attachments/assets/3ee8df11-ac9a-42ee-8bd9-b7460ef5bfba" />
<img width="1171" height="931" alt="Screenshot 2026-05-19 014534" src="https://github.com/user-attachments/assets/f712c341-2444-46a6-949f-93edac867253" />

## Installation

Pre-built packages in this repository:

| Format | Package | Size |
|--------|---------|------|
| **Debian/Ubuntu** | [`bytesweep_1.0.0_all.deb`](./bytesweep_1.0.0_all.deb) | 17 KB |
| **Fedora/RHEL** | [`bytesweep-1.0.0-1.noarch.rpm`](./bytesweep-1.0.0-1.noarch.rpm) | 26 KB |
| **AppImage** | [`ByteSweep-1.0.0-x86_64.AppImage`](./ByteSweep-1.0.0-x86_64.AppImage) | 6.5 MB |
| **Arch Linux** | [`PKGBUILD`](./PKGBUILD) + [`bytesweep.install`](./bytesweep.install) | Source |
| **Snap** | [`snap/snapcraft.yaml`](./snap/snapcraft.yaml) | Source |

### Debian / Ubuntu / Linux Mint / Pop!_OS

```bash
wget https://github.com/iu2vwk-ita/swiftserver/raw/main/bytesweep_1.0.0_all.deb
sudo dpkg -i bytesweep_1.0.0_all.deb
```

### Fedora / RHEL / CentOS / Rocky Linux

```bash
wget https://github.com/iu2vwk-ita/swiftserver/raw/main/bytesweep-1.0.0-1.noarch.rpm
sudo rpm -i bytesweep-1.0.0-1.noarch.rpm
```

### AppImage (any Linux)

```bash
wget https://github.com/iu2vwk-ita/swiftserver/raw/main/ByteSweep-1.0.0-x86_64.AppImage
chmod +x ByteSweep-1.0.0-x86_64.AppImage
./ByteSweep-1.0.0-x86_64.AppImage
```

### Arch Linux

```bash
git clone https://github.com/iu2vwk-ita/swiftserver.git
cd swiftserver
makepkg -si
```

### Universal script (any Linux)

```bash
curl -sSL https://raw.githubusercontent.com/iu2vwk-ita/swiftserver/main/install.sh | sudo bash
```

---

After installation, the dashboard is available at **http://your-server-ip:5000**

## Service Management

```bash
# Check service status
sudo systemctl status bytesweep

# Restart the service
sudo systemctl restart bytesweep

# Stop the service
sudo systemctl stop bytesweep

# View live logs
sudo journalctl -u bytesweep -f

# Check auto-cleanup timer
sudo systemctl status bytesweep-cleanup.timer
```

## Uninstall

### Debian/Ubuntu
```bash
sudo apt remove bytesweep      # Remove (keeps config)
sudo apt purge bytesweep        # Remove everything
```

### Fedora/RHEL
```bash
sudo rpm -e bytesweep
```

### Arch Linux
```bash
sudo pacman -R bytesweep        # Remove
sudo pacman -Rns bytesweep      # Remove with dependencies
```

### AppImage
```bash
# Just delete the file and stop the process
pkill -f server_monitor.py
rm ByteSweep-*.AppImage
```

## Quick Start (Development)

```bash
git clone https://github.com/iu2vwk-ita/swiftserver.git
cd swiftserver
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python server_monitor.py
```

## Configuration

Edit `/opt/server-monitor/config.py` (or `config.py` for development):

```python
SERVER_PORT = 5000          # Dashboard port
SERVER_HOST = "0.0.0.0"     # Bind address
UPDATE_INTERVAL = 2         # Seconds between metric refreshes
ENABLE_TEMPS = True         # Enable temperature sensor reading
LOG_LEVEL = "INFO"          # Logging verbosity
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI (HTML) |
| `/api/system` | GET | Hostname, platform, uptime, CPU count, memory total |
| `/api/metrics` | GET | Full real-time metrics snapshot |
| `/api/cpu` | GET | CPU usage, per-core breakdown, load average |
| `/api/ram` | GET | Memory usage statistics |
| `/api/disk` | GET | Disk partition usage |
| `/api/network` | GET | Network I/O counters |
| `/api/cleanup/status` | GET | List available cleaners and estimated savings |
| `/api/cleanup/run` | POST | Run selected cleaners (JSON body: `{"items": ["apt","journal"]}`) |
| `/api/files/list` | GET | List directory contents (`?path=/opt`) |
| `/api/files/delete` | POST | Delete file or directory (`{"path": "/opt/old-folder"}`) |

## Cleaners

The cleanup module supports 10 maintenance operations:

| ID | Target | Description |
|----|--------|-------------|
| `apt` | APT Cache | Remove downloaded packages and run autoremove |
| `journal` | Systemd Logs | Limit journal retention to 200 MB |
| `syslogs` | Old Syslogs | Delete rotated log archives |
| `snap` | Snap Packages | Remove old revisions and cache |
| `docker` | Docker Images | Prune unused images, containers, and networks |
| `pip` | Pip Cache | Purge Python package download cache |
| `npm` | npm Cache | Clear Node.js package cache |
| `browsers` | Browser Caches | Remove Playwright / Puppeteer / Electron downloads |
| `tmp` | Temp Files | Delete `/tmp` files older than 1 day |
| `uv` | UV Cache | Clear UV Python package manager cache |

## Auto-Cleanup Agent

The auto-cleanup agent runs every hour via systemd timer. It checks disk usage and automatically triggers all cleaners if any partition exceeds **90%** full.

```bash
# Check agent status
sudo systemctl status bytesweep-cleanup.timer

# Run manually
sudo /opt/server-monitor/venv/bin/python /opt/server-monitor/auto_cleanup.py

# View agent logs
tail -f /opt/server-monitor/logs/cleanup.log
```

## Project Structure

```
swiftserver/
├── server_monitor.py    # Flask application + API endpoints
├── cleanup.py           # Cleanup engine (10 maintenance operations)
├── auto_cleanup.py      # Background agent for automated cleanup
├── config.py            # Server and logging configuration
├── requirements.txt     # Python dependencies
├── install.sh           # Universal install script (all distros)
│
├── build-deb.sh         # Debian/Ubuntu package builder
├── debian/              # Debian package control files
│   └── DEBIAN/
│       ├── control
│       ├── postinst
│       ├── postrm
│       └── conffiles
│
├── build-rpm.sh         # Fedora/RHEL package builder
├── rpm/                 # RPM build files
│   └── bytesweep.spec
│
├── PKGBUILD             # Arch Linux package build
├── bytesweep.install    # Arch post-install hooks
├── build-arch.sh        # Arch package helper
│
├── build-appimage.sh    # AppImage builder
├── snap/                # Snapcraft configuration
│   └── snapcraft.yaml
│
└── static/
    └── index.html       # Dashboard frontend (vanilla JS + Chart.js)
```

## Requirements

- Python 3.8+
- Linux with systemd (recommended for production)
- Root access required for cleanup operations

**Dependencies:**
- Flask 3.0.0
- psutil 5.9.8
- netifaces 0.11.0

## License

MIT
