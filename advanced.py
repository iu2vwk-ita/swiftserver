#!/usr/bin/env python3
"""
ByteSweep Advanced Security Module
Scheduled scans, firewall, auto-kill, integrity monitor, log viewer.
"""

import os
import re
import json
import time
import hashlib
import threading
import subprocess
import logging
import urllib.request
import urllib.error
from datetime import datetime

log = logging.getLogger("bytesweep.advanced")

# ── Global state ────────────────────────────────────────────────

_scheduler_running = False
_scheduler_thread = None
_scheduler_interval = 3600  # default 1 hour
_auto_kill_miners = False
_integrity_hashes = {}
INTEGRITY_FILE = "/opt/server-monitor/logs/integrity.json"
SCHEDULER_STATE_FILE = "/opt/server-monitor/logs/scheduler.json"


# ── 1. Scheduled Scan Engine ────────────────────────────────────

def start_scheduler(interval_seconds=3600, alert_webhook=None):
    global _scheduler_running, _scheduler_thread, _scheduler_interval
    if _scheduler_running:
        return {"success": False, "message": "Scheduler already running"}

    _scheduler_interval = interval_seconds
    _scheduler_running = True

    def _scan_loop():
        while _scheduler_running:
            time.sleep(_scheduler_interval)
            if not _scheduler_running:
                break
            try:
                from security import deep_forensic_scan
                result = deep_forensic_scan()
                _persist_scheduler_state(False, None)
                if result.get("total_findings", 0) > 0:
                    log.warning(f"Scheduled scan found {result['total_findings']} issues")
                    if alert_webhook:
                        _send_alert(alert_webhook, result)
                else:
                    log.info("Scheduled scan: clean")
            except Exception as e:
                log.error(f"Scheduled scan error: {e}")
                _persist_scheduler_state(True, str(e))

    _scheduler_thread = threading.Thread(target=_scan_loop, daemon=True)
    _scheduler_thread.start()
    _persist_scheduler_state(False, None)
    return {"success": True, "message": f"Scheduler started, interval: {interval_seconds}s"}


def stop_scheduler():
    global _scheduler_running
    _scheduler_running = False
    _persist_scheduler_state(False, "stopped")
    return {"success": True, "message": "Scheduler stopped"}


def scheduler_status():
    state = _load_json(SCHEDULER_STATE_FILE)
    return {
        "running": _scheduler_running,
        "interval": _scheduler_interval,
        "last_error": state.get("last_error"),
        "last_run": state.get("last_run"),
    }


def _persist_scheduler_state(error, message):
    _save_json(SCHEDULER_STATE_FILE, {
        "last_run": datetime.now().isoformat(),
        "last_error": message if error else None,
        "running": _scheduler_running,
    })


def _send_alert(webhook_url, scan_result):
    total = scan_result.get("total_findings", 0)
    sections = []
    for key, val in scan_result.items():
        if isinstance(val, dict) and val.get("findings_count", 0) > 0:
            sections.append(f"- {key}: {val['findings_count']} finding(s)")
    body = f"ByteSweep Alert: {total} threat(s) detected\n" + "\n".join(sections[:10])

    if "telegram" in webhook_url.lower():
        _send_telegram(webhook_url, body)
    else:
        _send_webhook(webhook_url, body)


def _send_telegram(bot_url, text):
    try:
        data = json.dumps({"chat_id": _extract_tg_chat_id(bot_url), "text": text, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(bot_url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.error(f"Telegram alert failed: {e}")


def _extract_tg_chat_id(url):
    m = re.search(r'chat_id=(-?\d+)', url)
    return m.group(1) if m else ""


def _send_webhook(url, text):
    try:
        data = json.dumps({"text": text, "timestamp": datetime.now().isoformat()}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.error(f"Webhook alert failed: {e}")


# ── 2. Firewall (iptables) ──────────────────────────────────────

def firewall_list_rules():
    """List current iptables rules."""
    rules = []
    try:
        for cmd_key, label in [("-L INPUT -n --line-numbers", "INPUT"), ("-L OUTPUT -n --line-numbers", "OUTPUT")]:
            r = subprocess.run(f"iptables {cmd_key}", shell=True, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line and line[0].isdigit():
                        rules.append({"chain": label, "rule": line})
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "rules": rules[:100], "count": len(rules)}


def firewall_block_ip(ip, port=None, direction="INPUT"):
    """Block an IP address. Optionally on a specific port."""
    try:
        if port:
            cmd = ["iptables", "-I", direction, "1", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"]
        else:
            cmd = ["iptables", "-I", direction, "1", "-s", ip, "-j", "DROP"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return {"success": False, "error": r.stderr.strip()}
        return {"success": True, "message": f"Blocked {ip}" + (f" on port {port}" if port else "")}
    except Exception as e:
        return {"success": False, "error": str(e)}


def firewall_unblock_ip(ip):
    """Remove all DROP rules for an IP."""
    try:
        r = subprocess.run(
            f"iptables -L INPUT -n --line-numbers | grep '{ip}' | grep DROP | awk '{{print $1}}' | sort -rn",
            shell=True, capture_output=True, text=True, timeout=5
        )
        for num in r.stdout.strip().splitlines():
            if num.isdigit():
                subprocess.run(["iptables", "-D", "INPUT", num], capture_output=True, timeout=5)
        r2 = subprocess.run(
            f"iptables -L OUTPUT -n --line-numbers | grep '{ip}' | grep DROP | awk '{{print $1}}' | sort -rn",
            shell=True, capture_output=True, text=True, timeout=5
        )
        for num in r2.stdout.strip().splitlines():
            if num.isdigit():
                subprocess.run(["iptables", "-D", "OUTPUT", num], capture_output=True, timeout=5)
        return {"success": True, "message": f"Unblocked {ip}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── 3. Auto-Kill Miner ──────────────────────────────────────────

def get_auto_kill():
    return {"enabled": _auto_kill_miners}


def set_auto_kill(enabled):
    global _auto_kill_miners
    _auto_kill_miners = bool(enabled)
    return {"success": True, "enabled": _auto_kill_miners}


def auto_kill_miners_if_enabled(mining_result):
    """Called after mining detection; kills known miners if auto-kill enabled."""
    if not _auto_kill_miners:
        return {"killed": 0, "message": "Auto-kill disabled"}
    killed = []
    for proc in mining_result.get("suspicious", []):
        if "known_miner" in proc.get("reason", ""):
            try:
                import psutil
                p = psutil.Process(proc["pid"])
                name = p.name()
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    p.kill()
                killed.append({"pid": proc["pid"], "name": name})
                log.warning(f"Auto-killed miner: {name} (PID {proc['pid']})")
            except Exception as e:
                log.error(f"Auto-kill failed for PID {proc['pid']}: {e}")
    return {"killed": len(killed), "processes": killed}


# ── 4. Integrity Monitor ────────────────────────────────────────

CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab",
    "/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/ssh",
    "/usr/bin/systemctl",
]


def integrity_baseline(paths=None):
    """Create baseline hashes for critical files."""
    global _integrity_hashes
    paths = paths or CRITICAL_FILES
    hashes = {}
    for fp in paths:
        if os.path.isfile(fp):
            try:
                hashes[fp] = _sha256_file(fp)
            except Exception:
                hashes[fp] = None
    _integrity_hashes = hashes
    _save_json(INTEGRITY_FILE, {"hashes": hashes, "created": datetime.now().isoformat()})
    return {"success": True, "files_hashed": len(hashes), "timestamp": datetime.now().isoformat()}


def integrity_check(paths=None):
    """Check critical files against baseline hashes."""
    global _integrity_hashes
    if not _integrity_hashes:
        data = _load_json(INTEGRITY_FILE)
        _integrity_hashes = data.get("hashes", {}) if data else {}

    paths = paths or list(_integrity_hashes.keys()) or CRITICAL_FILES
    changed = []
    ok = []
    missing = []

    for fp in paths:
        old_hash = _integrity_hashes.get(fp)
        if not os.path.isfile(fp):
            if old_hash:
                missing.append({"path": fp, "status": "deleted"})
            continue
        try:
            new_hash = _sha256_file(fp)
            if old_hash and new_hash != old_hash:
                changed.append({"path": fp, "status": "modified", "old_hash": old_hash[:16], "new_hash": new_hash[:16]})
            else:
                ok.append(fp)
        except Exception:
            missing.append({"path": fp, "status": "unreadable"})

    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "total": len(paths),
        "ok": len(ok),
        "changed": changed,
        "missing": missing,
        "has_baseline": bool(_integrity_hashes),
    }


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ── 5. Log Viewer ───────────────────────────────────────────────

LOG_PATHS = {
    "access": "/opt/server-monitor/logs/access.log",
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "cleanup": "/opt/server-monitor/logs/cleanup.log",
}


def log_viewer_list():
    """List available log files with sizes."""
    logs = []
    for name, path in LOG_PATHS.items():
        size = 0
        if os.path.isfile(path):
            size = os.path.getsize(path)
        logs.append({"name": name, "path": path, "size": size, "size_str": _fmt_bytes(size)})
    return {"logs": logs}


def log_viewer_read(log_name, lines=100, search=None, offset=0):
    """Read tail of a log file with optional search."""
    path = LOG_PATHS.get(log_name)
    if not path or not os.path.isfile(path):
        return {"success": False, "error": f"Log '{log_name}' not found"}

    try:
        all_lines = []
        with open(path, "r", errors="ignore") as f:
            all_lines = [l.rstrip() for l in f.readlines()]

        total_lines = len(all_lines)

        if search:
            search_lower = search.lower()
            all_lines = [l for i, l in enumerate(all_lines) if search_lower in l.lower()]

        start = max(0, len(all_lines) - lines - offset)
        result_lines = all_lines[start:start + lines]

        return {
            "success": True,
            "log": log_name,
            "total_lines": total_lines,
            "filtered_lines": len(all_lines),
            "returned_lines": len(result_lines),
            "lines": result_lines,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── JSON helpers ────────────────────────────────────────────────

def _load_json(path):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)
        os.chmod(path, 0o600)
        return True
    except Exception:
        return False


def _fmt_bytes(bytes_val):
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.1f} GB"
    if bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.1f} MB"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    return f"{bytes_val} B"
