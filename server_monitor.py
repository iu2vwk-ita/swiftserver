#!/usr/bin/env python3
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
from flask import Flask, jsonify, request
from datetime import datetime
import cleanup

app = Flask(__name__)

ALLOWED_ROOTS = ["/", "/home", "/opt", "/var", "/tmp"]

def _safe_path(path):
    """Normalize and validate path to prevent traversal attacks."""
    if not path:
        path = "/"
    path = os.path.abspath(os.path.normpath(path))
    # Allow any absolute path for local admin use, but block common sensitive paths
    blocked = ["/proc", "/sys", "/dev", "/run", "/boot"]
    for b in blocked:
        if path.startswith(b):
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
    """List directory contents with sizes."""
    path = _safe_path(path)
    items = []
    try:
        for entry in os.scandir(path):
            try:
                stat = entry.stat(follow_symlinks=False)
                mtime = stat.st_mtime
                if entry.is_dir(follow_symlinks=False):
                    # Get dir size via du for speed
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
    # Sort: dirs first, then alphabetically
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
    return processes[:10]

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

@app.route("/")
def index():
    return app.send_static_file("index.html")

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

# ── File Manager Endpoints ──

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
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return jsonify({"success": True, "path": path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    from config import SERVER_PORT, SERVER_HOST, UPDATE_INTERVAL, ENABLE_TEMPS, LOG_LEVEL
    import logging

    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    app.config['ENABLE_TEMPS'] = ENABLE_TEMPS

    logging.info(f"Starting Server Monitor on {SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False, threaded=True)
