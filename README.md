# SwiftServer

A lightweight, real-time Linux server monitoring dashboard with integrated disk cleanup utilities. Built with Flask and vanilla JavaScript for zero-dependency deployment.

## Features

- **Real-time Metrics** — Live CPU, memory, disk, and network charts (Chart.js)
- **System Overview** — Uptime, load average, CPU core count, temperature sensors
- **Top Processes** — Auto-updating table of the most CPU-intensive processes
- **Network Details** — Per-interface IP and MAC address discovery
- **Disk Visualization** — Partition usage with color-coded progress bars
- **One-Click Cleanup** — Web UI to run maintenance cleaners (APT, logs, Docker, caches)
- **Auto-Cleanup Agent** — Background timer that cleans automatically when disk exceeds 90%
- **Responsive Dark UI** — Works on desktop, tablet, and mobile

## Screenshots

<img width="1615" height="1024" alt="Screenshot 2026-05-18 171934" src="https://github.com/user-attachments/assets/a78b5d4c-737a-47d5-bd3c-56b1afb8a40d" />

<img width="795" height="479" alt="Screenshot 2026-05-18 170329" src="https://github.com/user-attachments/assets/d6518ddd-4fbe-4aa5-951c-7de52f6d28d2" />

Access the dashboard at `http://your-server-ip:5000` after starting the server.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/iu2vwk-ita/swiftserver.git
cd swiftserver
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the server

```bash
python server_monitor.py
```

The dashboard will be available at **http://0.0.0.0:5000**

## Installation (Production)

For a persistent system service with auto-cleanup:

```bash
chmod +x install.sh
sudo ./install.sh
```

This installs SwiftServer under `/opt/server-monitor/`, creates a `systemd` service, and optionally sets up the hourly auto-cleanup agent.

```bash
# Check service status
sudo systemctl status swiftserver

# View logs
sudo journalctl -u swiftserver -f
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

## Configuration

Edit `config.py` to customize behavior:

```python
SERVER_PORT = 5000          # Dashboard port
SERVER_HOST = "0.0.0.0"     # Bind address
UPDATE_INTERVAL = 2         # Seconds between metric refreshes
ENABLE_TEMPS = True         # Enable temperature sensor reading
LOG_LEVEL = "INFO"          # Logging verbosity
```

## Cleaners

The cleanup module supports the following maintenance operations:

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

The auto-cleanup agent runs every hour via `systemd` timer. It checks disk usage and automatically triggers all cleaners if any partition exceeds **90%** full.

```bash
# Check agent status
sudo systemctl status swiftserver-cleanup.timer

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
├── install.sh           # Production installation script
└── static/
    └── index.html       # Dashboard frontend (vanilla JS + Chart.js)
```

## Requirements

- Python 3.8+
- Linux with `systemd` (recommended for production)
- Root access required for cleanup operations

**Dependencies:**
- Flask 3.0.0
- psutil 5.9.8
- netifaces 0.11.0

## License

MIT
