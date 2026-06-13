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
ADVANCED_STATE_FILE = "/opt/server-monitor/logs/advanced_state.json"


def load_persisted_state():
    """Load auto-kill and scheduler state from disk. Call on startup."""
    global _auto_kill_miners
    state = _load_json(ADVANCED_STATE_FILE)
    if "auto_kill" in state:
        _auto_kill_miners = bool(state["auto_kill"])


def _save_advanced_state():
    _save_json(ADVANCED_STATE_FILE, {
        "auto_kill": _auto_kill_miners,
        "scheduler_running": _scheduler_running,
        "scheduler_interval": _scheduler_interval,
    })


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
                # Also run behavioral anomaly snapshot
                anomaly_snapshot()
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
    _save_advanced_state()
    return {"success": True, "message": f"Scheduler started, interval: {interval_seconds}s"}


def stop_scheduler():
    global _scheduler_running
    _scheduler_running = False
    _persist_scheduler_state(False, "stopped")
    _save_advanced_state()
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
    _save_advanced_state()
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


# ── 6. Behavioral Anomaly Logger ────────────────────────────────

ANOMALY_LOG = "/opt/server-monitor/logs/anomaly.log"
ANOMALY_STATE = "/opt/server-monitor/logs/anomaly_state.json"

# State snapshots
_last_process_snapshot = set()
_last_connection_snapshot = set()
_last_systemd_snapshot = set()
_last_cron_snapshot = set()


def anomaly_snapshot():
    """Take a behavioral snapshot and compare to previous, log anomalies."""
    global _last_process_snapshot, _last_connection_snapshot
    global _last_systemd_snapshot, _last_cron_snapshot

    # Load previous state
    prev = _load_json(ANOMALY_STATE)
    _last_process_snapshot = set(prev.get("processes", []))
    _last_connection_snapshot = set(prev.get("connections", []))
    _last_systemd_snapshot = set(prev.get("systemd_services", []))
    _last_cron_snapshot = set(prev.get("cron_entries", []))

    anomalies = []
    now = datetime.now().isoformat()

    # 1. New processes (PID ignored, compare (name, cmdline_hash))
    import hashlib as _hl
    current_procs = set()
    try:
        for p in psutil.process_iter(['name', 'cmdline']):
            try:
                cmd = ' '.join(p.info.get('cmdline') or [])
                key = f"{p.info['name']}|{_hl.md5(cmd.encode()).hexdigest()[:12]}"
                current_procs.add(key)
            except Exception:
                pass
    except Exception:
        pass

    new_procs = current_procs - _last_process_snapshot
    gone_procs = _last_process_snapshot - current_procs
    if new_procs:
        suspicious = [p for p in new_procs if any(x in p.lower() for x in
            ['miner', 'xmrig', 'stratum', 'cryptonight', 'zzh', 'rsysloged',
             'backdoor', 'reverse', 'c2', 'nezha', 'tor', 'hidden', '/tmp/',
             '/dev/shm/', '/var/tmp/', '/etc/.', '.so', 'LD_PRELOAD'])]
        if suspicious:
            anomalies.append({"type": "new_suspicious_process", "detail": suspicious, "time": now})
    if gone_procs and len(gone_procs) > 10:
        anomalies.append({"type": "many_processes_gone", "count": len(gone_procs), "time": now})

    # 2. New network connections (external only)
    current_conns = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                rip = conn.raddr.ip
                if not rip.startswith('127.') and not rip.startswith('192.168.') and not rip.startswith('10.') and not rip.startswith('172.16.'):
                    current_conns.add(f"{rip}:{conn.raddr.port}")
    except Exception:
        pass

    new_conns = current_conns - _last_connection_snapshot
    if new_conns:
        anomalies.append({"type": "new_external_connections", "detail": list(new_conns), "time": now})

    # 3. New systemd services
    current_systemd = set()
    for svc_dir in ["/etc/systemd/system", "/lib/systemd/system"]:
        if os.path.isdir(svc_dir):
            for fname in os.listdir(svc_dir):
                if fname.endswith(".service"):
                    current_systemd.add(fname)

    new_systemd = current_systemd - _last_systemd_snapshot
    gone_systemd = _last_systemd_snapshot - current_systemd
    if new_systemd:
        anomalies.append({"type": "new_systemd_services", "detail": list(new_systemd), "time": now})
    if gone_systemd:
        anomalies.append({"type": "removed_systemd_services", "detail": list(gone_systemd), "time": now})

    # 4. New cron entries
    current_cron = set()
    for cron_dir in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily"]:
        if os.path.isdir(cron_dir):
            for fname in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, fname)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath) as f:
                            current_cron.add(f"{fname}:{_hl.md5(f.read().encode()).hexdigest()[:12]}")
                    except Exception:
                        pass

    new_cron = current_cron - _last_cron_snapshot
    gone_cron = _last_cron_snapshot - current_cron
    if new_cron:
        anomalies.append({"type": "new_cron_entries", "detail": list(new_cron), "time": now})
    if gone_cron:
        anomalies.append({"type": "removed_cron_entries", "detail": list(gone_cron), "time": now})

    # Save current state
    _save_json(ANOMALY_STATE, {
        "processes": list(current_procs),
        "connections": list(current_conns),
        "systemd_services": list(current_systemd),
        "cron_entries": list(current_cron),
        "last_update": now,
    })

    _last_process_snapshot = current_procs
    _last_connection_snapshot = current_conns
    _last_systemd_snapshot = current_systemd
    _last_cron_snapshot = current_cron

    # Log anomalies
    if anomalies:
        os.makedirs(os.path.dirname(ANOMALY_LOG), exist_ok=True)
        with open(ANOMALY_LOG, "a") as f:
            for a in anomalies:
                f.write(json.dumps(a) + "\n")
        log.warning(f"Behavioral anomalies detected: {len(anomalies)}")

    return {"success": True, "anomalies": len(anomalies), "timestamp": now}


def anomaly_log_read(lines=100, search=None):
    """Read the anomaly log."""
    if not os.path.isfile(ANOMALY_LOG):
        return {"success": True, "entries": [], "total": 0}

    try:
        with open(ANOMALY_LOG, "r") as f:
            entries = [json.loads(l) for l in f.readlines() if l.strip()]

        if search:
            sl = search.lower()
            entries = [e for e in entries if sl in json.dumps(e).lower()]

        entries.reverse()
        return {
            "success": True,
            "total": len(entries),
            "entries": entries[:lines],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def anomaly_reset_baseline():
    """Delete anomaly state so next snapshot creates a new baseline."""
    if os.path.exists(ANOMALY_STATE):
        os.remove(ANOMALY_STATE)
    return {"success": True, "message": "Baseline reset. Next snapshot will be the new baseline."}


# ── 7. Intrusion Trace Layer ─────────────────────────────────────

HONEYTOKEN_DIR = "/opt/server-monitor/honeytokens"
TRACE_LOG = "/opt/server-monitor/logs/trace.log"
_ssh_monitor_thread = None
_ssh_monitor_running = False


def trace_log(entry_type, detail):
    """Write a trace entry for intrusion analysis."""
    entry = {"time": datetime.now().isoformat(), "type": entry_type, "detail": detail}
    os.makedirs(os.path.dirname(TRACE_LOG), exist_ok=True)
    try:
        with open(TRACE_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    log.warning(f"TRACE: {entry_type} - {str(detail)[:200]}")


def start_ssh_monitor():
    """Monitor auth.log in real-time for SSH logins."""
    global _ssh_monitor_thread, _ssh_monitor_running
    if _ssh_monitor_running:
        return {"success": False, "message": "SSH monitor already running"}

    _ssh_monitor_running = True

    def _watch():
        global _ssh_monitor_running
        auth_log = "/var/log/auth.log"
        if not os.path.exists(auth_log):
            auth_log = "/var/log/secure"
        if not os.path.exists(auth_log):
            log.error(f"SSH monitor: no auth log found")
            _ssh_monitor_running = False
            return

        try:
            last_pos = max(0, os.path.getsize(auth_log) - 8192)  # include last 8KB
            while _ssh_monitor_running:
                time.sleep(0.5)
                try:
                    cur_size = os.path.getsize(auth_log)
                    if cur_size > last_pos:
                        with open(auth_log, "r") as f:
                            f.seek(last_pos)
                            new_data = f.read(cur_size - last_pos)
                            last_pos = cur_size
                        for line in new_data.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            lower = line.lower()
                            if "accepted" in lower and ("ssh" in lower or "sshd" in lower):
                                parts = line.strip().split()
                                user = ip = ""
                                for i, p in enumerate(parts):
                                    if p == "for" and i + 1 < len(parts):
                                        user = parts[i + 1]
                                    if p == "from" and i + 1 < len(parts):
                                        ip = parts[i + 1]
                                if ip:
                                    trace_log("ssh_login_accepted", {"user": user, "ip": ip, "raw": line[:200]})
                                    _track_successful_login(ip, user)
                            elif "failed password" in lower or "authentication failure" in lower:
                                parts = line.strip().split()
                                ip = ""
                                for i, p in enumerate(parts):
                                    if p == "from" and i + 1 < len(parts):
                                        ip = parts[i + 1]
                                if ip:
                                    trace_log("ssh_login_failed", {"ip": ip, "raw": line[:200]})
                                    _track_failed_login(ip)
                            elif "session opened" in lower and "sudo" in lower:
                                trace_log("sudo_session", {"raw": line[:200]})
                    elif cur_size < last_pos:
                        # Log rotated - reset position
                        last_pos = 0
                except Exception:
                    pass
        except Exception as e:
            log.error(f"SSH monitor error: {e}")
        _ssh_monitor_running = False

    _ssh_monitor_thread = threading.Thread(target=_watch, daemon=True)
    _ssh_monitor_thread.start()
    trace_log("ssh_monitor_started", "Real-time SSH monitoring active")
    return {"success": True, "message": "SSH monitor started"}


def stop_ssh_monitor():
    global _ssh_monitor_running
    _ssh_monitor_running = False
    return {"success": True, "message": "SSH monitor stopped"}


def ssh_monitor_status():
    return {"running": _ssh_monitor_running}


def deploy_honeytokens():
    """Place bait files in common attacker locations. Any access is logged."""
    os.makedirs(HONEYTOKEN_DIR, exist_ok=True)
    tokens = {}

    # Fake credentials file
    token_path = os.path.join(HONEYTOKEN_DIR, "backup_credentials.txt")
    with open(token_path, "w") as f:
        f.write("# Database backup credentials\n")
        f.write("DB_HOST=prod-db.internal\n")
        f.write("DB_USER=admin\n")
        f.write("DB_PASS=SuperSecret123!\n")
    os.chmod(token_path, 0o400)
    tokens["credentials_file"] = token_path

    # Fake SSH key
    token_path = os.path.join(HONEYTOKEN_DIR, "id_rsa_backup")
    with open(token_path, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        f.write("(honeytoken - access is monitored)\n")
        f.write("-----END OPENSSH PRIVATE KEY-----\n")
    os.chmod(token_path, 0o400)
    tokens["ssh_key"] = token_path

    # Fake .env file
    token_path = os.path.join(HONEYTOKEN_DIR, ".env")
    with open(token_path, "w") as f:
        f.write("SECRET_KEY=production-secret-key-2024\n")
        f.write("API_TOKEN=sk-abcdef1234567890\n")
        f.write("DATABASE_URL=postgresql://admin:password@localhost/db\n")
    os.chmod(token_path, 0o400)
    tokens["env_file"] = token_path

    # Plant token in /tmp disguised as cache
    os.makedirs("/tmp/.cache_bkp", exist_ok=True)
    token_path = "/tmp/.cache_bkp/id_rsa"
    with open(token_path, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n(honeytoken)\n-----END OPENSSH PRIVATE KEY-----\n")
    tokens["tmp_ssh_key"] = token_path

    # Plant token in /var/tmp
    os.makedirs("/var/tmp/.sys", exist_ok=True)
    token_path = "/var/tmp/.sys/config.json"
    with open(token_path, "w") as f:
        f.write('{"honeytoken": true, "note": "access monitored"}\n')
    tokens["var_tmp_config"] = token_path

    # Plant token in /etc (attacker favorite)
    token_path = "/etc/.syscfg"
    os.makedirs(token_path, exist_ok=True)
    cfg_path = os.path.join(token_path, "db.conf")
    with open(cfg_path, "w") as f:
        f.write("[database]\npassword = ProductionDB2024!\n")
    tokens["etc_syscfg"] = cfg_path

    trace_log("honeytokens_deployed", {"count": len(tokens), "paths": list(tokens.values())})

    return {"success": True, "tokens_deployed": len(tokens), "paths": list(tokens.values())}


def check_honeytokens():
    """Check if any honeytoken files have been accessed (atime/mtime changed)."""
    triggered = []
    if not os.path.isdir(HONEYTOKEN_DIR):
        return {"triggered": 0, "tokens": []}

    baseline_file = os.path.join(HONEYTOKEN_DIR, ".baseline.json")
    baseline = _load_json(baseline_file)

    for root, _, files in os.walk(HONEYTOKEN_DIR):
        for fname in files:
            if fname == ".baseline.json":
                continue
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                key = fpath
                old = baseline.get(key, {})
                if old and (st.st_atime != old.get("atime") or st.st_mtime != old.get("mtime")):
                    triggered.append({
                        "path": fpath,
                        "old_atime": old.get("atime"),
                        "new_atime": st.st_atime,
                    })
                    trace_log("honeytoken_accessed", {"path": fpath, "atime": st.st_atime})
            except Exception:
                pass

    # Also check planted tokens outside HONEYTOKEN_DIR
    planted = ["/tmp/.cache_bkp/id_rsa", "/var/tmp/.sys/config.json", "/etc/.syscfg/db.conf"]
    for pp in planted:
        if os.path.exists(pp):
            try:
                st = os.stat(pp)
                key = pp
                old = baseline.get(key, {})
                if old and (st.st_atime != old.get("atime") or st.st_mtime != old.get("mtime")):
                    triggered.append({
                        "path": pp,
                        "old_atime": old.get("atime"),
                        "new_atime": st.st_atime,
                    })
                    trace_log("honeytoken_accessed", {"path": pp, "atime": st.st_atime})
            except Exception:
                pass

    # Update baseline
    new_baseline = {}
    for root, _, files in os.walk(HONEYTOKEN_DIR):
        for fname in files:
            if fname == ".baseline.json":
                continue
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                new_baseline[fpath] = {"atime": st.st_atime, "mtime": st.st_mtime}
            except Exception:
                pass
    for pp in planted:
        if os.path.exists(pp):
            try:
                st = os.stat(pp)
                new_baseline[pp] = {"atime": st.st_atime, "mtime": st.st_mtime}
            except Exception:
                pass
    _save_json(baseline_file, new_baseline)

    return {"triggered": len(triggered), "tokens": triggered}


def trace_log_read(lines=50, search=None):
    """Read the trace log."""
    if not os.path.isfile(TRACE_LOG):
        return {"success": True, "entries": [], "total": 0}
    try:
        with open(TRACE_LOG, "r") as f:
            entries = [json.loads(l) for l in f.readlines() if l.strip()]
        if search:
            sl = search.lower()
            entries = [e for e in entries if sl in json.dumps(e).lower()]
        entries.reverse()
        return {"success": True, "total": len(entries), "entries": entries[:lines]}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── 8. Auto-Ban System ──────────────────────────────────────────

AUTOBAN_STATE = "/opt/server-monitor/logs/autoban.json"
_failed_attempts = {}
_successful_ips = set()
_banned_ips = set()
_auto_ban_lock = threading.Lock()
WHITELIST_IPS = {"127.0.0.1", "::1"}
AUTOBAN_THRESHOLD = 5
AUTOBAN_WINDOW = 300
AUTOBAN_DURATION = 0


def _is_whitelisted(ip):
    if ip in WHITELIST_IPS or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "::1":
        return True
    return False


def _ban_ip(ip, reason):
    if _is_whitelisted(ip):
        return
    with _auto_ban_lock:
        if ip in _banned_ips:
            return
        _banned_ips.add(ip)
    try:
        subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], capture_output=True, timeout=5)
        trace_log("autoban_ip", {"ip": ip, "reason": reason})
        log.warning(f"AUTO-BAN: {ip} — {reason}")
        _save_json(AUTOBAN_STATE, {"banned": list(_banned_ips), "successful": list(_successful_ips)})
    except Exception as e:
        log.error(f"Auto-ban failed for {ip}: {e}")


def _unban_ip(ip):
    with _auto_ban_lock:
        _banned_ips.discard(ip)
    for chain in ["INPUT", "OUTPUT"]:
        try:
            r = subprocess.run(
                f"iptables -L {chain} -n --line-numbers 2>/dev/null | grep '{ip}' | grep DROP | awk '{{print $1}}' | sort -rn",
                shell=True, capture_output=True, text=True, timeout=5
            )
            for num in r.stdout.strip().splitlines():
                if num.isdigit():
                    subprocess.run(["iptables", "-D", chain, num], capture_output=True, timeout=5)
        except Exception:
            pass
    _save_json(AUTOBAN_STATE, {"banned": list(_banned_ips), "successful": list(_successful_ips)})


def load_autoban_state():
    global _banned_ips, _successful_ips
    state = _load_json(AUTOBAN_STATE)
    if "banned" in state:
        _banned_ips = set(state["banned"])
    if "successful" in state:
        _successful_ips = set(state["successful"])


def _track_failed_login(ip):
    if _is_whitelisted(ip):
        return False
    now = datetime.now()
    with _auto_ban_lock:
        attempts = [t for t in _failed_attempts.get(ip, []) if (now - t).total_seconds() < AUTOBAN_WINDOW]
        attempts.append(now)
        _failed_attempts[ip] = attempts
        count = len(attempts)
    if count >= AUTOBAN_THRESHOLD:
        _ban_ip(ip, f"{count} failed logins in {AUTOBAN_WINDOW}s")
        with _auto_ban_lock:
            _failed_attempts.pop(ip, None)
        return True
    return False


def _track_successful_login(ip, user):
    if _is_whitelisted(ip):
        return
    with _auto_ban_lock:
        is_new = ip not in _successful_ips
        _successful_ips.add(ip)
    if is_new:
        trace_log("new_ip_login", {"ip": ip, "user": user})
        log.warning(f"NEW IP LOGIN: {user} from {ip}")
    _save_json(AUTOBAN_STATE, {"banned": list(_banned_ips), "successful": list(_successful_ips)})


def autoban_status():
    return {"banned_count": len(_banned_ips), "banned_ips": sorted(_banned_ips),
            "threshold": AUTOBAN_THRESHOLD, "window_s": AUTOBAN_WINDOW}


def autoban_unban(ip):
    _unban_ip(ip)
    return {"success": True, "message": f"Unbanned {ip}"}
