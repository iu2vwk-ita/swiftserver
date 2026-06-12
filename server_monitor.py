#!/usr/bin/env python3
"""
ByteSweep Server Monitor - Flask application
"""
import psutil
import netifaces
import time
import platform
import socket
import json
import threading
import os
import shutil
import subprocess
import select
import pty
import fcntl
import termios
import struct
import uuid
import hashlib
import hmac
import logging
import functools
import secrets
import re
from flask import Flask, jsonify, request, g
from flask_sock import Sock
from datetime import datetime, timedelta

import cleanup
import security
import advanced

app = Flask(__name__)
sock = Sock(app)

# ── Global state ────────────────────────────────────────────────

_sessions = {}            # token -> {"created": datetime, "ip": str}
_lock = threading.Lock()
_runtime_password = None   # Runtime password (can be changed from panel)
_runtime_salt = None       # Per-server salt for password hashing
SETTINGS_FILE = "/opt/server-monitor/logs/settings.json"
MAX_SESSIONS = 100

# Rate limiting
_login_attempts = {}       # ip -> [(timestamp, ...)]
_lock_login = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60

ALLOWED_ROOTS = ["/", "/home", "/opt", "/var", "/tmp"]

# ── Session cleanup ─────────────────────────────────────────────

def _session_cleanup():
    """Periodically remove expired sessions."""
    with _lock:
        now = datetime.now()
        expired = [
            t for t, s in _sessions.items()
            if now - s["created"] > timedelta(hours=app.config.get('SESSION_EXPIRY_HOURS', 4))
        ]
        for t in expired:
            _sessions.pop(t, None)

# ── Password helpers ────────────────────────────────────────────

def _hash_password(password):
    """Hash password with PBKDF2-HMAC-SHA256 (100k iterations) and per-server salt."""
    global _runtime_salt
    if not _runtime_salt:
        _runtime_salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), _runtime_salt.encode(), 100000).hex()


def _constant_time_compare(a, b):
    """Constant-time string comparison using hmac.compare_digest."""
    return hmac.compare_digest(a.encode() if isinstance(a, str) else a,
                                b.encode() if isinstance(b, str) else b)


# ── Runtime settings persistence ────────────────────────────────

def _load_settings():
    global _runtime_password, _runtime_salt
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
                _runtime_salt = data.get("salt")
                pw_hash = data.get("panel_password_hash")
                if pw_hash and _runtime_salt:
                    _runtime_password = pw_hash  # store hash in memory
                    app.config['PANEL_PASSWORD'] = pw_hash
    except Exception:
        pass


def _save_settings(data):
    global _runtime_password, _runtime_salt
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        existing = {}
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                existing = json.load(f)
        existing.update(data)
        # Remove old plaintext password field if present (migration from v1)
        existing.pop("panel_password", None)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(existing, f)
        os.chmod(SETTINGS_FILE, 0o600)
        if "panel_password_hash" in data:
            _runtime_password = data["panel_password_hash"]
            app.config['PANEL_PASSWORD'] = _runtime_password
        if "salt" in data:
            _runtime_salt = data["salt"]
        return True
    except Exception:
        return False


# ── Auth helpers ────────────────────────────────────────────────

def _get_password():
    """Get effective password hash: runtime > config file."""
    if _runtime_password is not None:
        return _runtime_password
    return app.config.get('PANEL_PASSWORD')


def _require_auth():
    """Check auth. Returns True if allowed, False if auth required and missing."""
    if not _get_password():
        return True
    token = request.headers.get('X-Auth-Token') or request.cookies.get('byte_token')
    if not token or token not in _sessions:
        return False
    s = _sessions[token]
    if datetime.now() - s["created"] > timedelta(hours=app.config.get('SESSION_EXPIRY_HOURS', 4)):
        with _lock:
            _sessions.pop(token, None)
        return False
    return True


def auth_required(f):
    """Decorator: require auth when password is set."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not _require_auth():
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper


# ── Access logging middleware ───────────────────────────────────

@app.before_request
def _access_log_start():
    g._req_start = time.time()


@app.after_request
def _access_log_end(response):
    if not app.config.get('ACCESS_LOG'):
        return response

    duration = (time.time() - g.get('_req_start', 0)) * 1000
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    method = request.method
    path = request.path
    status = response.status_code
    user_agent = (request.headers.get('User-Agent', '-') or '-')[:200]

    # Do NOT log auth-related request bodies or tokens in URL
    safe_path = path
    if '/api/auth/login' in path or '/api/settings' in path:
        safe_path = re.sub(r'(password=)[^&\s]+', r'\1***', path)

    log_line = f'{ts} {ip} "{method} {safe_path}" {status} {duration:.1f}ms "{user_agent}"'

    log_file = app.config.get('ACCESS_LOG_FILE', '/tmp/bytesweep-access.log')
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(log_file, 'a') as f:
            f.write(log_line + '\n')
    except Exception:
        pass

    return response


# ── Auth API ────────────────────────────────────────────────────

@app.route("/api/auth/status")
def auth_status():
    return jsonify({
        "auth_enabled": bool(_get_password()),
        "authenticated": _require_auth()
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    password_hash = _get_password()
    if not password_hash:
        return jsonify({"success": True, "token": None, "message": "Authentication not configured"})

    # Rate limiting
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = datetime.now()
    with _lock_login:
        attempts = [t for t in _login_attempts.get(ip, []) if (now - t).total_seconds() < LOGIN_WINDOW_SECONDS]
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            logging.warning(f"Rate limit hit for IP {ip}")
            return jsonify({"success": False, "error": "Too many attempts. Try again later."}), 429
        attempts.append(now)
        _login_attempts[ip] = attempts

    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")

    if not _constant_time_compare(_hash_password(pw), password_hash):
        return jsonify({"success": False, "error": "Invalid password"}), 401

    # Cleanup old sessions before creating new one
    _session_cleanup()
    with _lock:
        if len(_sessions) >= MAX_SESSIONS:
            oldest = min(_sessions.keys(), key=lambda k: _sessions[k]["created"])
            _sessions.pop(oldest, None)

    token = secrets.token_hex(32)
    with _lock:
        _sessions[token] = {"created": datetime.now(), "ip": ip}

    # Clear rate limit on successful login
    with _lock_login:
        _login_attempts.pop(ip, None)

    resp = jsonify({"success": True, "token": token})
    resp.set_cookie("byte_token", token, httponly=True, samesite='Strict', secure=False)
    return resp


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.headers.get('X-Auth-Token') or request.cookies.get('byte_token')
    if token:
        with _lock:
            _sessions.pop(token, None)
    resp = jsonify({"success": True})
    resp.delete_cookie("byte_token")
    return resp


# ── Settings API (auth required when password set) ──────────────

@app.route("/api/settings")
def settings_get():
    pw = _get_password()
    return jsonify({
        "password_enabled": bool(pw),
        "password_set": bool(pw),
    })


@app.route("/api/settings", methods=["POST"])
@auth_required
def settings_post():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    if action == "set_password":
        new_pw = data.get("password", "")
        if not new_pw or len(new_pw) < 4:
            return jsonify({"success": False, "error": "Password must be at least 4 characters"}), 400
        pw_hash = _hash_password(new_pw)
        ok = _save_settings({"panel_password_hash": pw_hash, "salt": _runtime_salt})
        with _lock:
            _sessions.clear()
        return jsonify({"success": ok, "message": "Password set. All sessions invalidated."})

    elif action == "disable_password":
        ok = _save_settings({"panel_password_hash": None})
        with _lock:
            _sessions.clear()
        return jsonify({"success": ok, "message": "Password protection disabled."})

    return jsonify({"success": False, "error": f"Unknown action: {action}"}), 400


# ── Utility functions ───────────────────────────────────────────

def _safe_path(path):
    """Normalize and validate path to prevent traversal attacks."""
    if not path:
        path = "/"
    path = os.path.abspath(os.path.normpath(path))
    # Resolve symlinks to prevent /home/user/link -> /proc bypass
    try:
        path = os.path.realpath(path)
    except Exception:
        path = "/"
    blocked = ["/proc", "/sys", "/dev", "/run", "/boot"]
    for b in blocked:
        if path == b or path.startswith(b + "/"):
            return "/"
    return path


def _size_str(size):
    if size >= 1073741824:
        return f"{size / 1073741824:.1f} GB"
    if size >= 1048576:
        return f"{size / 1048576:.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _list_dir(path):
    path = _safe_path(path)
    items = []
    try:
        for entry in os.scandir(path):
            try:
                stat = entry.stat(follow_symlinks=False)
                mtime = stat.st_mtime
                if entry.is_dir(follow_symlinks=False):
                    try:
                        r = subprocess.run(["du", "-sb", entry.path], capture_output=True, text=True, timeout=5)
                        size = int(r.stdout.split()[0]) if r.returncode == 0 else 0
                    except Exception:
                        size = 0
                    items.append({
                        "name": entry.name,
                        "type": "dir",
                        "size": size,
                        "size_str": _size_str(size),
                        "mtime": mtime
                    })
                else:
                    items.append({
                        "name": entry.name,
                        "type": "file",
                        "size": stat.st_size,
                        "size_str": _size_str(stat.st_size),
                        "mtime": mtime
                    })
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass
    items.sort(key=lambda x: (0 if x["type"] == "dir" else 1, x["name"].lower()))
    return items


def _get_dir_size(path):
    try:
        r = subprocess.run(["du", "-sb", path], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return int(r.stdout.split()[0])
    except Exception:
        pass
    return 0


def get_cpu():
    return psutil.cpu_percent(interval=1, percpu=False)


def get_cpu_cores():
    return psutil.cpu_percent(interval=1, percpu=True)


def get_ram():
    mem = psutil.virtual_memory()
    return {
        "total": mem.total,
        "used": mem.used,
        "free": mem.free,
        "percent": mem.percent
    }


def get_disk():
    partitions = psutil.disk_partitions()
    disks = []
    for p in partitions:
        try:
            usage = psutil.disk_usage(p.mountpoint)
            disks.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent
            })
        except:
            pass
    return disks


def get_network():
    net = psutil.net_io_counters()
    return {
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
        "errin": net.errin,
        "errout": net.errout,
        "dropin": net.dropin,
        "dropout": net.dropout
    }


def get_network_ifaces():
    ifaces = {}
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if iface == 'lo':
            continue
        if 2 in addrs:
            for addr in addrs[2]:
                if 'addr' in addr:
                    if iface not in ifaces:
                        ifaces[iface] = {"ip": addr['addr'], "mac": ""}
        if 17 in addrs:
            for addr in addrs[17]:
                if 'addr' in addr:
                    if iface in ifaces:
                        ifaces[iface]["mac"] = addr['addr']
    return ifaces


def get_load():
    load = psutil.getloadavg()
    return {"1min": load[0], "5min": load[1], "15min": load[2]}


def get_top_processes():
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append({
                "pid": p.info['pid'],
                "name": p.info['name'],
                "cpu": p.info['cpu_percent'],
                "mem": p.info['memory_percent']
            })
        except:
            pass
    processes.sort(key=lambda x: x.get('cpu', 0), reverse=True)
    return processes[:15]


def get_temps():
    temps = []
    try:
        for entry in psutil.sensors_temperatures():
            for sensor in entry:
                temps.append({
                    "label": sensor.label or entry.label,
                    "current": sensor.current,
                    "high": sensor.high,
                    "critical": sensor.critical
                })
    except:
        pass
    return temps


def get_uptime():
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    now = datetime.now()
    uptime = now - boot_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return {"days": days, "hours": hours, "minutes": minutes, "seconds": seconds}


def _html_escape(text):
    """Escape HTML entities to prevent XSS."""
    if isinstance(text, (int, float)):
        return str(text)
    if not isinstance(text, str):
        return str(text)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#x27;"))


# ── Page Routes ─────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")


# ── System API ──────────────────────────────────────────────────

@app.route("/api/system")
def system_info():
    return jsonify({
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "cpu_physical": psutil.cpu_count(logical=False),
        "memory_total": psutil.virtual_memory().total,
        "disk_total": sum(d['total'] for d in get_disk()),
        "uptime": get_uptime(),
        "load": get_load()
    })


@app.route("/api/metrics")
def metrics():
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
        "ram": get_ram(),
        "disk": get_disk(),
        "network": get_network(),
        "network_ifaces": get_network_ifaces(),
        "load": get_load(),
        "temps": get_temps() if app.config.get('ENABLE_TEMPS') else [],
        "top_processes": get_top_processes()
    })


@app.route("/api/cpu")
def cpu_data():
    return jsonify({"cpu": get_cpu(), "cores": get_cpu_cores(), "load": get_load()})


@app.route("/api/ram")
def ram_data():
    return jsonify(get_ram())


@app.route("/api/disk")
def disk_data():
    return jsonify(get_disk())


@app.route("/api/network")
def network_data():
    return jsonify(get_network())


@app.route("/api/cleanup/status")
def cleanup_status():
    return jsonify({"items": cleanup.get_status()})


@app.route("/api/cleanup/run", methods=["POST"])
def cleanup_run():
    data = request.get_json(silent=True) or {}
    items = data.get("items", None)
    result = cleanup.run_cleanup(items)
    return jsonify(result)


# ── Process Kill API ────────────────────────────────────────────

@app.route("/api/process/kill", methods=["POST"])
@auth_required
def process_kill():
    data = request.get_json(silent=True) or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"success": False, "error": "PID required"}), 400
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid PID"}), 400
    if pid <= 1:
        return jsonify({"success": False, "error": "Cannot kill PID 0 or 1 (init/systemd)"}), 400
    # Prevent killing the server itself
    try:
        proc = psutil.Process(pid)
        if proc.ppid() == os.getpid() or pid == os.getpid():
            return jsonify({"success": False, "error": "Cannot kill server process"}), 400
    except Exception:
        pass
    result = security.kill_process(pid)
    status = 200 if result["success"] else 400
    return jsonify(result), status


# ── Security API ────────────────────────────────────────────────

@app.route("/api/security/clamav-status")
def clamav_status():
    import shutil as _sh
    has_clamav = bool(_sh.which("clamscan") or _sh.which("clamdscan"))
    return jsonify({"installed": has_clamav})


@app.route("/api/security/virus-scan", methods=["POST"])
def virus_scan():
    paths = app.config.get('VIRUS_SCAN_PATHS', ["/tmp", "/var/tmp", "/home"])
    timeout = min(app.config.get('VIRUS_SCAN_TIMEOUT', 300), 600)  # cap at 10 min
    data = request.get_json(silent=True) or {}
    if "paths" in data:
        user_paths = data["paths"]
        if isinstance(user_paths, list):
            # Validate user-provided paths
            safe_paths = []
            for p in user_paths:
                sp = _safe_path(p)
                if sp != "/" or p == "/":
                    safe_paths.append(sp)
            paths = safe_paths[:10]  # max 10 paths
    if "timeout" in data:
        try:
            timeout = min(int(data["timeout"]), 600)
        except (ValueError, TypeError):
            pass
    result = security.scan_virus(paths, timeout=timeout)
    return jsonify(result)


@app.route("/api/security/install-clamav", methods=["POST"])
def install_clamav():
    import shutil as _sh
    if _sh.which("clamscan") or _sh.which("clamdscan"):
        return jsonify({"success": True, "already_installed": True, "message": "ClamAV is already installed"})

    # Only allow on Debian-based systems
    if not os.path.exists("/etc/debian_version"):
        return jsonify({"success": False, "error": "Auto-install only supported on Debian/Ubuntu. Install manually."}), 400

    try:
        r = subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            err = (r.stderr[:200] or "apt update failed").strip()
            return jsonify({"success": False, "error": err}), 500

        r = subprocess.run(
            ["apt-get", "install", "-y", "-qq", "clamav", "clamav-daemon"],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode != 0:
            err = (r.stderr[:200] or "apt install failed").strip()
            return jsonify({"success": False, "error": err}), 500

        subprocess.run(["freshclam", "--quiet"], capture_output=True, timeout=120)

        installed = bool(_sh.which("clamscan") or _sh.which("clamdscan"))
        return jsonify({"success": installed, "message": "ClamAV installed successfully" if installed else "Install check failed"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Installation timed out"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/security/mine-detect")
def mine_detect():
    cpu_threshold = app.config.get('MINING_CPU_THRESHOLD', 50)
    patterns = app.config.get('MINING_PATTERNS', None)
    result = security.detect_mining(cpu_threshold=cpu_threshold, known_patterns=patterns)
    # Auto-kill if enabled
    kill_result = advanced.auto_kill_miners_if_enabled(result)
    result["auto_kill"] = kill_result
    return jsonify(result)


@app.route("/api/security/ports")
def security_ports():
    threshold = app.config.get('RECENT_PORT_THRESHOLD', 300)
    result = security.get_open_ports(recent_threshold=threshold)
    return jsonify(result)


@app.route("/api/security/forensic-scan")
def forensic_scan():
    result = security.deep_forensic_scan()
    return jsonify(result)


# ── Scheduled Scan API ──────────────────────────────────────────

@app.route("/api/security/scheduler")
def scheduler_status_api():
    return jsonify(advanced.scheduler_status())


@app.route("/api/security/scheduler/start", methods=["POST"])
def scheduler_start():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 3600)
    webhook = data.get("webhook_url")
    result = advanced.start_scheduler(interval_seconds=int(interval), alert_webhook=webhook)
    return jsonify(result)


@app.route("/api/security/scheduler/stop", methods=["POST"])
def scheduler_stop():
    result = advanced.stop_scheduler()
    return jsonify(result)


# ── Firewall API ────────────────────────────────────────────────

@app.route("/api/security/firewall/rules")
def firewall_rules():
    return jsonify(advanced.firewall_list_rules())


@app.route("/api/security/firewall/block", methods=["POST"])
def firewall_block():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    port = data.get("port")
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    result = advanced.firewall_block_ip(ip, port=port)
    return jsonify(result)


@app.route("/api/security/firewall/unblock", methods=["POST"])
def firewall_unblock():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    result = advanced.firewall_unblock_ip(ip)
    return jsonify(result)


# ── Geolocation API ─────────────────────────────────────────────

@app.route("/api/security/geolocate")
def geolocate_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip == "0.0.0.0" or ip == "::1":
        return jsonify({"success": False, "error": "Private/reserved IP"}), 400
    try:
        import urllib.request as _ur
        req = _ur.Request(f"http://ip-api.com/json/{ip}?fields=country,city,regionName,lat,lon,isp,org",
                          headers={"User-Agent": "ByteSweep/2.0"})
        with _ur.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "fail":
            return jsonify({"success": False, "error": data.get("message", "Unknown IP")})
        return jsonify({
            "success": True, "ip": ip,
            "country": data.get("country", ""), "city": data.get("city", ""),
            "region": data.get("regionName", ""), "lat": data.get("lat"),
            "lon": data.get("lon"), "isp": data.get("isp", ""), "org": data.get("org", ""),
            "map_url": f"https://www.openstreetmap.org/?mlat={data.get('lat')}&mlon={data.get('lon')}&zoom=10" if data.get("lat") else None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Auto-Kill Miner API ─────────────────────────────────────────

@app.route("/api/security/auto-kill")
def auto_kill_status():
    return jsonify(advanced.get_auto_kill())


@app.route("/api/security/auto-kill", methods=["POST"])
def auto_kill_toggle():
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", False)
    result = advanced.set_auto_kill(enabled)
    return jsonify(result)


# ── Integrity Monitor API ───────────────────────────────────────

@app.route("/api/security/integrity/baseline", methods=["POST"])
def integrity_baseline():
    result = advanced.integrity_baseline()
    return jsonify(result)


@app.route("/api/security/integrity/check")
def integrity_check():
    result = advanced.integrity_check()
    return jsonify(result)


# ── Log Viewer API ──────────────────────────────────────────────

@app.route("/api/security/logs")
def log_viewer_list():
    return jsonify(advanced.log_viewer_list())


@app.route("/api/security/logs/<log_name>")
def log_viewer_read(log_name):
    lines = request.args.get("lines", 100, type=int)
    search = request.args.get("search")
    offset = request.args.get("offset", 0, type=int)
    result = advanced.log_viewer_read(log_name, lines=min(lines, 500), search=search, offset=offset)
    return jsonify(result)


# ── File Manager ────────────────────────────────────────────────

@app.route("/api/files/list")
def files_list():
    path = request.args.get("path", "/")
    path = _safe_path(path)
    items = _list_dir(path)
    total_size = _get_dir_size(path)
    return jsonify({
        "path": path,
        "items": items,
        "total_size": total_size,
        "total_size_str": _size_str(total_size)
    })


@app.route("/api/files/delete", methods=["POST"])
def files_delete():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    path = _safe_path(path)
    if not os.path.exists(path):
        return jsonify({"success": False, "error": "Path not found"}), 404
    # Prevent deletion of critical paths
    if path in ("/", "/bin", "/sbin", "/etc", "/usr", "/var", "/opt", "/home") or path.startswith("/boot"):
        return jsonify({"success": False, "error": "Cannot delete system directory"}), 403
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return jsonify({"success": True, "path": path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Web Terminal (with auth) ────────────────────────────────────

def _ws_auth_ok():
    """Check auth for WebSocket connections (supports query param token for WS)."""
    if not _get_password():
        return True
    # WebSocket can't use headers/cookies easily everywhere; support token query param
    token = request.args.get('token', '') or request.headers.get('X-Auth-Token', '')
    if not token or token not in _sessions:
        return False
    s = _sessions[token]
    if datetime.now() - s["created"] > timedelta(hours=app.config.get('SESSION_EXPIRY_HOURS', 4)):
        with _lock:
            _sessions.pop(token, None)
        return False
    return True


@sock.route('/ws/terminal')
def terminal_ws(ws):
    if not _ws_auth_ok():
        ws.send(b'Authentication required. Login first.\r\n')
        ws.close()
        return

    child_pid, fd = pty.fork()
    if child_pid == 0:
        os.environ['TERM'] = 'xterm-256color'
        os.environ['HOME'] = os.path.expanduser('~')
        os.execve('/bin/bash', ['/bin/bash'], os.environ)
    else:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def read_pty():
            while True:
                try:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if r:
                        data = os.read(fd, 8192)
                        if not data:
                            break
                        ws.send(data)
                except Exception:
                    break

        t = threading.Thread(target=read_pty, daemon=True)
        t.start()

        while True:
            try:
                data = ws.receive()
                if data is None:
                    break
                if isinstance(data, str):
                    data = data.encode()
                os.write(fd, data)
            except Exception:
                break

        os.close(fd)
        try:
            os.waitpid(child_pid, 0)
        except Exception:
            pass


@sock.route('/ws/terminal/resize')
def terminal_resize_ws(ws):
    while True:
        try:
            data = ws.receive()
            if data is None:
                break
            msg = json.loads(data)
            cols = msg.get('cols', 80)
            rows = msg.get('rows', 24)
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCSWINSZ, winsize)
        except Exception:
            break


# ── Main ────────────────────────────────────────────────────────

if __name__ == "__main__":
    from config import (SERVER_PORT, SERVER_HOST, UPDATE_INTERVAL, ENABLE_TEMPS,
                        LOG_LEVEL, ACCESS_LOG, ACCESS_LOG_FILE, PANEL_PASSWORD,
                        SESSION_EXPIRY_HOURS, VIRUS_SCAN_PATHS, VIRUS_SCAN_TIMEOUT,
                        MINING_CPU_THRESHOLD, MINING_PATTERNS, RECENT_PORT_THRESHOLD,
                        LOG_DIR, SCHEDULED_SCAN_INTERVAL, ALERT_WEBHOOK_URL,
                        AUTO_KILL_MINERS)

    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

    app.config['ENABLE_TEMPS'] = ENABLE_TEMPS
    app.config['ACCESS_LOG'] = ACCESS_LOG
    app.config['ACCESS_LOG_FILE'] = ACCESS_LOG_FILE or "/opt/server-monitor/logs/access.log"
    app.config['PANEL_PASSWORD'] = PANEL_PASSWORD
    app.config['SESSION_EXPIRY_HOURS'] = SESSION_EXPIRY_HOURS
    app.config['VIRUS_SCAN_PATHS'] = VIRUS_SCAN_PATHS
    app.config['VIRUS_SCAN_TIMEOUT'] = VIRUS_SCAN_TIMEOUT
    app.config['MINING_CPU_THRESHOLD'] = MINING_CPU_THRESHOLD
    app.config['MINING_PATTERNS'] = MINING_PATTERNS
    app.config['RECENT_PORT_THRESHOLD'] = RECENT_PORT_THRESHOLD

    os.makedirs(LOG_DIR or "/opt/server-monitor/logs", exist_ok=True)

    # Load runtime settings
    _load_settings()
    advanced.load_persisted_state()

    # Auto-start scheduled scanner if configured
    if SCHEDULED_SCAN_INTERVAL > 0:
        advanced.start_scheduler(interval_seconds=SCHEDULED_SCAN_INTERVAL, alert_webhook=ALERT_WEBHOOK_URL)
        logging.info(f"Scheduled scan started: every {SCHEDULED_SCAN_INTERVAL}s")

    # Auto-enable miner killing if configured
    if AUTO_KILL_MINERS:
        advanced.set_auto_kill(True)
        logging.info("Auto-kill miners: ENABLED")

    pw = _get_password()
    if pw:
        logging.info("Panel password protection ENABLED")
    else:
        logging.info("Panel password protection DISABLED")

    logging.info(f"Starting Server Monitor on {SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False, threaded=True)
