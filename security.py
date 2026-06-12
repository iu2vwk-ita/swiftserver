#!/usr/bin/env python3
"""
ByteSweep Security Module
Forensic scan: mining, backdoors, rootkits, C2 agents, persistence, suspicious files.
"""

import os
import re
import json
import time
import shutil
import struct
import psutil
import subprocess
import logging
from datetime import datetime

log = logging.getLogger("bytesweep.security")

# ── Known malicious indicators ──────────────────────────────────

KNOWN_MINING_POOLS = [
    "pool.supportxmr.com", "pool.minexmr.com", "moneroocean.stream",
    "pool.hashvault.pro", "xmr.pool.minergate.com", "cryptonight",
    "stratum+tcp://", "xmr-eu1.nanopool.org", "xmr.2miners.com",
    "c3pool.com", "mine.c3pool.com", "pool.c3pool.com",
]

KNOWN_C2_AGENTS = [
    "nezha", "agent-nz", "nz-agent", "nezha-agent",
    "cobalt", "sliver", "merlin",
]

KNOWN_ROOTKIT_SIGNS = [
    "ld.so.preload", "LD_PRELOAD",
]

KNOWN_BACKDOOR_PATTERNS = [
    "@@@lulzsecita@@@",
]

SUSPICIOUS_SYSTEMD = [
    "avachi", "named", "xm", "kworker", "kthread", "syslog", "audit",
]

SUSPICIOUS_CRON_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/root/.cache/",
]

REVERSE_SHELL_INDICATORS = [
    "/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "bash -i >&",
    "python -c 'import socket", "python -c \"import socket",
    "socket.socket(socket.AF_INET",
]

KNOWN_DROPPER_DOMAINS = [
    "nulltrafficaway", "project-lab-test",
]


# ── File helpers ────────────────────────────────────────────────

def _file_size(path):
    try: return os.path.getsize(path)
    except OSError: return 0


def _read_file(path, max_lines=200):
    try:
        with open(path, "r", errors="ignore") as f:
            return [l.rstrip() for l in f.readlines()[:max_lines]]
    except Exception:
        return []


def _run_cmd(cmd, timeout=10, shell=False):
    try:
        if shell:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


# ── Deep Forensics Scan ─────────────────────────────────────────

def deep_forensic_scan():
    """Run a comprehensive forensic security scan."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "success": True,
        "hidden_dirs": _scan_hidden_dirs(),
        "suspicious_binaries": _scan_suspicious_binaries(),
        "backdoor_ssh": _scan_backdoor_ssh(),
        "rootkit_signs": _scan_rootkits(),
        "suspicious_cron": _scan_cron_jobs(),
        "suspicious_systemd": _scan_systemd_services(),
        "c2_agents": _scan_c2_agents(),
        "reverse_shells": _scan_reverse_shells(),
        "mining_connections": _scan_mining_connections(),
        "ld_preload": _scan_ld_preload(),
    }
    # Summary
    total_findings = 0
    for key, val in results.items():
        if isinstance(val, dict) and "findings" in val:
            total_findings += len(val["findings"])
        elif isinstance(val, list):
            total_findings += len(val)
    results["total_findings"] = total_findings
    return results


# ── 1. Hidden Directories in system paths ───────────────────────

def _scan_hidden_dirs():
    """Find hidden directories in /bin, /usr/bin, /etc, /tmp, /var/tmp, /opt"""
    findings = []
    scan_roots = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/etc", "/tmp", "/var/tmp", "/opt", "/root", "/home"]
    # Legitimate hidden dirs to skip
    SKIP_DIRS = {
        ".java", ".XIM-unix", ".X11-unix", ".ICE-unix", ".font-unix", ".Test-unix",
        ".pki", ".cache", ".npm", ".config", ".local", ".ssh", ".gnupg", ".docker",
        ".systemd-private-", ".cpan", ".cpanm",
        ".gradle", ".m2", ".sdkman", ".cargo", ".rustup", ".gem", ".bundle",
        ".nvm", ".node-gyp", ".electron-gyp", ".pyenv", ".venv", ".virtualenvs",
        ".opencode", ".claude", ".codeium", ".vscode-server", ".cursor-server",
        ".continue", ".aider", ".crewai", ".langchain", ".chroma",
    }

    for root in scan_roots:
        if not os.path.isdir(root):
            continue
        try:
            for entry in os.listdir(root):
                if not entry.startswith("."):
                    continue
                # Skip known legitimate hidden dirs
                if any(entry == s or entry.startswith(s) for s in SKIP_DIRS):
                    continue
                full_path = os.path.join(root, entry)
                if os.path.isdir(full_path) and not os.path.islink(full_path):
                    try:
                        size = _dir_size_fast(full_path)
                    except Exception:
                        size = 0
                    findings.append({
                        "type": "hidden_directory",
                        "path": full_path,
                        "name": entry,
                        "size": size,
                        "size_str": _fmt_bytes(size),
                        "severity": "high" if root in ("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/etc", "/tmp") else "medium"
                    })
        except PermissionError:
            pass

    findings.sort(key=lambda x: (0 if x["severity"] == "high" else 1, -x["size"]))
    return {"scanned_paths": scan_roots, "findings_count": len(findings), "findings": findings}


# ── 2. Suspicious large binaries in system dirs ────────────────

def _scan_suspicious_binaries():
    """Find large binary files in /etc, /tmp, /var/tmp, /dev/shm that are unusual."""
    findings = []
    scan_roots = ["/etc", "/tmp", "/var/tmp", "/dev/shm"]
    min_size = 10 * 1024 * 1024  # 10 MB
    SKIP_PREFIXES = ["/etc/alternatives/", "/etc/ssl/", "/etc/ca-certificates/"]

    for root in scan_roots:
        if not os.path.exists(root):
            continue
        try:
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    # Skip symlinks and known safe paths
                    if os.path.islink(fpath):
                        continue
                    if any(fpath.startswith(p) for p in SKIP_PREFIXES):
                        continue
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize > min_size:
                            ext = os.path.splitext(fname)[1].lower()
                            is_elf = _is_elf_file(fpath)
                            is_upx = _is_upx_packed(fpath) if is_elf else False
                            findings.append({
                                "type": "suspicious_binary",
                                "path": fpath,
                                "size": fsize,
                                "size_str": _fmt_bytes(fsize),
                                "is_elf": is_elf,
                                "is_upx_packed": is_upx,
                                "extension": ext,
                                "severity": "critical" if (is_elf and not ext) else "high"
                            })
                    except (OSError, PermissionError):
                        pass
        except PermissionError:
            pass

    findings.sort(key=lambda x: -x["size"])
    return {"min_size_mb": min_size // (1024 * 1024), "findings_count": len(findings), "findings": findings[:30]}


# ── 3. Backdoor SSH detection ──────────────────────────────────

def _scan_backdoor_ssh():
    """Detect backdoored SSH: non-standard ports, suspicious keys, weird configs."""
    findings = []

    # Check sshd listening on non-standard ports
    _, out, _ = _run_cmd(["ss", "-tlnp"])
    for line in out.splitlines():
        if "sshd" in line.lower():
            parts = line.split()
            for p in parts:
                if ":" in p and not p.startswith("["):
                    port = p.rsplit(":", 1)[-1]
                    if port.isdigit() and port not in ("22", "0"):
                        findings.append({
                            "type": "nonstandard_ssh_port",
                            "port": int(port),
                            "detail": line.strip(),
                            "severity": "high"
                        })

    # Check authorized_keys for unusual entries
    auth_keys_paths = [
        "/root/.ssh/authorized_keys",
        os.path.expanduser("~/.ssh/authorized_keys"),
    ]
    for akp in auth_keys_paths:
        if os.path.isfile(akp):
            lines = _read_file(akp)
            for i, line in enumerate(lines):
                if not line or line.startswith("#"):
                    continue
                if any(p in line.lower() for p in KNOWN_BACKDOOR_PATTERNS):
                    findings.append({
                        "type": "suspicious_ssh_key",
                        "path": akp,
                        "line": i + 1,
                        "content": line[:200],
                        "severity": "critical"
                    })

    # Check /etc/ssh/sshd_config for PermitRootLogin and weird ports
    sshd_cfg = _read_file("/etc/ssh/sshd_config")
    for line in sshd_cfg:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        if "permitrootlogin" in lower and "yes" in lower and "without-password" not in lower:
            findings.append({
                "type": "permit_root_login",
                "config": "/etc/ssh/sshd_config",
                "detail": stripped,
                "severity": "medium"
            })

    return {"findings_count": len(findings), "findings": findings}


# ── 4. LD_PRELOAD rootkit detection ────────────────────────────

def _scan_ld_preload():
    """Check for LD_PRELOAD in environment and /etc/ld.so.preload."""
    findings = []

    # Check /etc/ld.so.preload
    if os.path.isfile("/etc/ld.so.preload"):
        content = _read_file("/etc/ld.so.preload", max_lines=20)
        non_empty = [l for l in content if l.strip()]
        if non_empty:
            findings.append({
                "type": "ld_preload_file",
                "path": "/etc/ld.so.preload",
                "content": non_empty,
                "severity": "critical"
            })

    # Check environment for LD_PRELOAD across all processes
    for proc in psutil.process_iter(['pid', 'name', 'environ']):
        try:
            env = proc.info.get('environ')
            if env:
                for key in env:
                    if 'LD_PRELOAD' in key.upper():
                        findings.append({
                            "type": "ld_preload_env",
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "variable": key,
                            "value": env[key][:200],
                            "severity": "critical"
                        })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return {"findings_count": len(findings), "findings": findings}


# ── 5. Rootkit signs ───────────────────────────────────────────

def _scan_rootkits():
    """Scan for rootkit indicators."""
    findings = []

    # Hidden kernel modules (lsmod vs /proc/modules)
    try:
        visible = set()
        _, out, _ = _run_cmd(["lsmod"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts:
                visible.add(parts[0])

        proc_mods = _read_file("/proc/modules")
        proc_names = set()
        for line in proc_mods:
            parts = line.split()
            if parts:
                proc_names.add(parts[0])

        hidden_mods = proc_names - visible
        for mod in hidden_mods:
            findings.append({
                "type": "hidden_kernel_module",
                "module": mod,
                "severity": "critical"
            })
    except Exception:
        pass

    # Check for known rootkit files
    known_rt_files = [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf.d/*.conf",
    ]
    for pattern in known_rt_files:
        import glob as _glob
        for fp in _glob.glob(pattern):
            if os.path.isfile(fp):
                for line in _read_file(fp):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(s in line for s in ["/tmp/", "/var/tmp/", "/dev/shm/", ".so"]):
                        findings.append({
                            "type": "suspicious_library_path",
                            "file": fp,
                            "path": line,
                            "severity": "high"
                        })

    return {"findings_count": len(findings), "findings": findings}


# ── 6. Suspicious cron jobs ────────────────────────────────────

def _scan_cron_jobs():
    """Scan all crontabs for suspicious entries."""
    findings = []
    cron_dirs = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                 "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs"]

    # Check /etc/cron.d files
    if os.path.isdir("/etc/cron.d"):
        for fname in os.listdir("/etc/cron.d"):
            fpath = os.path.join("/etc/cron.d", fname)
            if os.path.isfile(fpath):
                for i, line in enumerate(_read_file(fpath)):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    severity, reason = _score_cron_line(line, fname)
                    if severity:
                        findings.append({
                            "type": "suspicious_cron",
                            "source": f"cron.d/{fname}",
                            "line": i + 1,
                            "content": line[:300],
                            "reason": reason,
                            "severity": severity
                        })

    # Check user crontabs
    for uid in ["root"] + _get_system_users():
        out = _get_user_crontab(uid)
        for i, line in enumerate(out.splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            severity, reason = _score_cron_line(line, f"crontab({uid})")
            if severity:
                findings.append({
                    "type": "suspicious_cron",
                    "source": f"crontab({uid})",
                    "line": i + 1,
                    "content": line[:300],
                    "reason": reason,
                    "severity": severity
                })

    # Check @reboot entries specifically
    for uid in ["root"] + _get_system_users():
        out = _get_user_crontab(uid)
        for i, line in enumerate(out.splitlines()):
            line_lower = line.strip().lower()
            if "@reboot" in line_lower:
                findings.append({
                    "type": "reboot_persistence",
                    "source": f"crontab({uid})",
                    "line": i + 1,
                    "content": line[:300],
                    "severity": "high"
                })

    findings.sort(key=lambda x: 0 if x["severity"] == "critical" else (1 if x["severity"] == "high" else 2))
    return {"findings_count": len(findings), "findings": findings}


def _score_cron_line(line, source):
    """Score a cron line's suspiciousness. Returns (severity, reason) or (None, None)."""
    lower = line.lower()

    # Skip known system cron files
    KNOWN_SYSTEM_CRONS = {"e2scrub_all", "man-db", "dpkg", "apt", "cracklib", "passwd",
                          "update-", "logrotate", "mlocate", "popularity-contest", "php",
                          "anacron", "apport", "certbot", "snapd", "fstrim", "btrfs"}
    source_base = os.path.basename(source.replace("cron.d/", "").replace("crontab(", "").replace(")", ""))
    if any(source_base.startswith(s) for s in KNOWN_SYSTEM_CRONS):
        return None, None

    # Check for tmp paths (but not /run/ which is normal systemd)
    if any(p.lower() in lower for p in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
        return "critical", f"uses path in suspicious location"

    # Check for mining patterns
    for mp in KNOWN_MINING_POOLS + KNOWN_C2_AGENTS:
        if mp.lower() in lower:
            return "critical", f"references known malicious pattern: {mp}"

    # Check for hidden dirs in system paths
    if "/." in line and any(x in line for x in ["/bin/", "/usr/", "/etc/", "/root/", "/tmp/", "/var/", "/opt/"]):
        return "high", "references hidden directory"

    # Check for curl/wget to IP or piping
    if any(x in lower for x in ["curl ", "wget "]):
        if any(x in line for x in ["|", ";", ">&", "/tmp", "/dev/shm"]):
            return "high", "suspicious download + pipe pattern"

    return None, None


# ── 7. Suspicious systemd services ─────────────────────────────

def _scan_systemd_services():
    """Find suspicious or hidden systemd services."""
    findings = []
    service_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]

    # Known legitimate services - skip these entirely
    SAFE_SERVICES = {
        "docker", "containerd", "plymouth", "wpa_supplicant", "dbus", "network",
        "ssh", "sshd", "systemd", "getty", "cron", "rsyslog", "syslog",
        "user", "session", "timers.target", "paths.target", "slices.target",
        "sockets.target", "local-fs", "remote-fs", "swap", "tmp", "resolved",
        "timesyncd", "journald", "logind", "udevd", "networkd", "bluetooth",
        "ufw", "firewalld", "ModemManager", "NetworkManager", "polkit",
        "accounts-daemon", "rtkit-daemon", "upower", "colord", "gdm",
        "lightdm", "sddm", "cups", "avahi", "snapd", "apport", "whoopsie",
        "kerneloops", "irqbalance", "apparmor", "unattended-upgrades",
        "packagekit", "bolt", "fwupd", "thermald", "nginx", "apache2",
        "httpd", "mysql", "mariadb", "postgresql", "redis", "bytesweep",
    }

    for svc_dir in service_dirs:
        if not os.path.isdir(svc_dir):
            continue
        for fname in os.listdir(svc_dir):
            if not fname.endswith(".service"):
                continue
            fpath = os.path.join(svc_dir, fname)
            base_name = fname.replace(".service", "")

            # Skip known safe services
            if base_name in SAFE_SERVICES:
                continue
            if any(base_name.startswith(s + "@") or base_name.startswith(s + "-") for s in SAFE_SERVICES):
                continue
            if any(base_name.startswith(s) for s in ["system-", "user-", "session-"]):
                continue
            if base_name.endswith(".mount") or base_name.endswith(".swap") or base_name.endswith(".slice"):
                continue

            try:
                content = _read_file(fpath)
                full_text = "\n".join(content)
                severity = None
                reason = ""

                # Check for suspicious service names
                for sp in SUSPICIOUS_SYSTEMD:
                    if sp.lower() in base_name.lower():
                        severity = "high"
                        reason = f"suspicious service name matching pattern '{sp}'"
                        break

                if severity:
                    pass  # Already found

                # Check for /tmp, /var/tmp, /dev/shm in ExecStart
                for line in content:
                    stripped = line.strip()
                    if not stripped.startswith("ExecStart="):
                        continue
                    exec_cmd = stripped.split("=", 1)[1]
                    for sp in ["/tmp/", "/var/tmp/", "/dev/shm/"]:
                        if sp in exec_cmd:
                            severity = "critical"
                            reason = f"ExecStart uses path {sp}"
                            break
                    if severity:
                        break

                # Check for hidden dirs in paths
                if not severity:
                    for p in ["/bin/.", "/usr/bin/.", "/sbin/.", "/usr/sbin/.", "/etc/."]:
                        if p in full_text:
                            severity = "high"
                            reason = f"references hidden directory {p}"
                            break

                if severity:
                    findings.append({
                        "type": "suspicious_systemd",
                        "path": fpath,
                        "name": fname,
                        "reason": reason,
                        "severity": severity,
                        "content_preview": full_text[:500]
                    })
            except Exception:
                pass

    findings.sort(key=lambda x: 0 if x["severity"] == "critical" else 1)
    return {"findings_count": len(findings), "findings": findings}


# ── 8. C2 Agent detection ──────────────────────────────────────

def _scan_c2_agents():
    """Detect known C2 agents like Nezha."""
    findings = []

    # Check process names for known C2 agents
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            info = proc.info
            name = (info['name'] or '').lower()
            cmdline = ' '.join(info['cmdline'] or []).lower()

            for agent in KNOWN_C2_AGENTS:
                if agent.lower() in name or agent.lower() in cmdline:
                    findings.append({
                        "type": "known_c2_agent",
                        "pid": info['pid'],
                        "name": info['name'],
                        "agent_pattern": agent,
                        "cmdline": cmdline[:300],
                        "severity": "critical"
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Check connections to known C2 ports using net_connections
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                rport = conn.raddr.port
                if rport in (5555, 8008, 4433, 50051, 8001, 55551):
                    try:
                        pname = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                    except Exception:
                        pname = "unknown"
                    findings.append({
                        "type": "c2_suspicious_connection",
                        "pid": conn.pid,
                        "name": pname,
                        "remote": f"{conn.raddr.ip}:{rport}",
                        "severity": "high"
                    })
    except Exception:
        pass

    return {"findings_count": len(findings), "findings": findings}


# ── 9. Reverse shell detection ─────────────────────────────────

def _scan_reverse_shells():
    """Detect processes that match reverse shell patterns."""
    findings = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            info = proc.info
            cmdline = ' '.join(info['cmdline'] or [])
            cmdline_lower = cmdline.lower()

            for indicator in REVERSE_SHELL_INDICATORS:
                if indicator.lower() in cmdline_lower:
                    findings.append({
                        "type": "reverse_shell_pattern",
                        "pid": info['pid'],
                        "name": info['name'],
                        "pattern_matched": indicator,
                        "cmdline": cmdline[:400],
                        "severity": "critical"
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return {"findings_count": len(findings), "findings": findings}


# ── 10. Mining pool connections ────────────────────────────────

def _scan_mining_connections():
    """Check established connections for known mining pool IPs/domains."""
    findings = []

    _, out, _ = _run_cmd(
        "ss -tnp state established 2>/dev/null | grep -v '127.0.0.1\\|::1'",
        shell=True, timeout=10
    )

    for line in out.splitlines():
        for pool in KNOWN_MINING_POOLS:
            if pool.lower() in line.lower():
                findings.append({
                    "type": "mining_pool_connection",
                    "pool": pool,
                    "detail": line.strip(),
                    "severity": "critical"
                })
                break

    # Also check process connections via psutil
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                rip = conn.raddr.ip
                rport = conn.raddr.port
                # Common mining ports: 3333, 4444, 5555, 8080, 14444, 55555
                if rport in (3333, 4444, 5555, 8080, 14444, 55555, 7777, 9999):
                    try:
                        pname = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                    except Exception:
                        pname = "unknown"
                    findings.append({
                        "type": "suspicious_mining_port",
                        "pid": conn.pid,
                        "name": pname,
                        "remote": f"{rip}:{rport}",
                        "severity": "high"
                    })
    except Exception:
        pass

    return {"findings_count": len(findings), "findings": findings}


# ── Individual scan functions (for API) ─────────────────────────

def scan_virus(paths, timeout=300):
    """Run ClamAV scan on given paths."""
    if not paths:
        return {"error": "No paths to scan", "success": False}

    clamav_bin = shutil.which("clamscan") or shutil.which("clamdscan")
    if not clamav_bin:
        return {
            "success": False,
            "error": "ClamAV not installed. Install with: apt install clamav clamav-daemon",
            "scanned": False
        }

    results = []
    total_infected = 0

    for path in paths:
        if not os.path.exists(path):
            results.append({"path": path, "infected": 0, "files": 0, "error": "Path not found"})
            continue
        try:
            cmd = [clamav_bin, "--no-summary", "-r", path]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = r.stdout + r.stderr
            infected_files = []
            for line in output.splitlines():
                if "FOUND" in line:
                    infected_files.append(line.strip())
            results.append({
                "path": path,
                "files_scanned": _count_scanned(output),
                "infected": len(infected_files),
                "infected_files": infected_files[:50],
                "success": True
            })
            total_infected += len(infected_files)
        except subprocess.TimeoutExpired:
            results.append({"path": path, "infected": 0, "files": 0, "error": "Scan timed out"})
        except Exception as e:
            results.append({"path": path, "infected": 0, "files": 0, "error": str(e)})

    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "total_infected": total_infected,
        "results": results,
        "clamav": clamav_bin
    }


def _count_scanned(output):
    m = re.search(r'Scanned (?:directories and )?(\d+) files?', output)
    if m: return int(m.group(1))
    m = re.search(r'Known viruses:.*\n.*Scanned:\s+(\d+)', output, re.DOTALL)
    if m: return int(m.group(1))
    return 0


def detect_mining(cpu_threshold=50, known_patterns=None):
    """Detect potential crypto mining processes."""
    if known_patterns is None:
        known_patterns = ["xmrig", "cpuminer", "minergate", "t-rex", "phoenixminer",
                          "lolminer", "nbminer", "gminer", "ethminer", "claymore",
                          "teamredminer", "cryptominer", "xmr-stak", "sgminer",
                          "cgminer", "bfgminer", "minerd", "ccminer", "cpuminer-opt",
                          "qgisring", "softwaretech"]

    suspicious = []
    mining_names = set()
    high_cpu = []

    proc_data = {}
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
        try:
            info = p.info
            proc_data[info['pid']] = info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(0.5)
    for pid, info in proc_data.items():
        try:
            p = psutil.Process(pid)
            cpu = p.cpu_percent()
            name = info['name'] or ''
            cmdline = ' '.join(info['cmdline'] or [])
            name_lower = name.lower()
            cmdline_lower = cmdline.lower()
            exe_path = ""
            try:
                exe_path = p.exe()
            except Exception:
                pass

            matched = False
            match_pattern = ""
            for pattern in known_patterns:
                if pattern in name_lower or pattern in cmdline_lower or pattern in exe_path.lower():
                    matched = True
                    match_pattern = pattern
                    break

            if matched:
                mining_names.add(pid)
                suspicious.append({
                    "pid": pid,
                    "name": name,
                    "cpu": round(cpu, 1),
                    "mem": info.get('memory_percent', 0),
                    "reason": f"known_miner:{match_pattern}",
                    "cmdline": cmdline[:200],
                    "exe": exe_path
                })
            elif cpu > cpu_threshold:
                high_cpu.append({
                    "pid": pid,
                    "name": name,
                    "cpu": round(cpu, 1),
                    "mem": info.get('memory_percent', 0),
                    "cmdline": cmdline[:200],
                    "exe": exe_path
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for proc in high_cpu:
        if proc['pid'] not in mining_names:
            proc["reason"] = "high_cpu"
            suspicious.append(proc)

    suspicious.sort(key=lambda x: x['cpu'], reverse=True)

    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "suspicious_count": len(suspicious),
        "suspicious": suspicious[:25],
        "cpu_threshold": cpu_threshold
    }


# ── Open Ports ──────────────────────────────────────────────────

def get_open_ports(recent_threshold=300):
    """Get recently active and listening ports."""
    ports = {
        "listening": [],
        "established": [],
        "recent": [],
        "suspicious_ports": [],
        "timestamp": datetime.now().isoformat()
    }

    try:
        listening = _parse_ss_listening()
        if listening:
            ports["listening"] = listening
        else:
            ports["listening"] = _parse_proc_net_tcp("0A")
        # Flag suspicious ports
        SUSPICIOUS_PORTS = {22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389,
                            5432, 6379, 8080, 8443, 9200, 11211, 27017, 50022, 50050}
        for entry in ports["listening"]:
            try:
                pnum = int(entry.get("port", 0))
                if pnum not in (0, 80, 443, 5000) and pnum not in SUSPICIOUS_PORTS:
                    if pnum > 1024:  # Non-standard high port
                        entry["suspicious"] = True
                        ports["suspicious_ports"].append(entry)
            except ValueError:
                pass
    except Exception as e:
        log.warning(f"Port scan failed: {e}")

    try:
        ss_est = _parse_ss_established()
        if ss_est:
            ports["established"] = ss_est
        else:
            ports["established"] = _parse_proc_net_tcp("01")
    except Exception as e:
        log.warning(f"Established ports failed: {e}")

    try:
        recent = _get_recent_connections(recent_threshold)
        ports["recent"] = recent
    except Exception as e:
        log.warning(f"Recent connections failed: {e}")

    ports["total_listening"] = len(ports["listening"])
    ports["total_established"] = len(ports["established"])
    ports["total_recent"] = len(ports["recent"])
    ports["total_suspicious"] = len(ports["suspicious_ports"])
    ports["success"] = True

    return ports


def _parse_ss_listening():
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return []
        entries = []
        for line in r.stdout.splitlines():
            if not line.startswith("LISTEN"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            process = ""
            if len(parts) >= 6:
                process = " ".join(parts[5:]).strip()
            addr, port = _split_addr_port(local)
            entries.append({
                "protocol": "tcp",
                "address": addr,
                "port": port,
                "process": process
            })
        return entries
    except Exception:
        return []


def _parse_ss_established():
    try:
        r = subprocess.run(["ss", "-tn", "state", "established"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return []
        entries = []
        for line in r.stdout.splitlines():
            if "ESTAB" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[3]
            remote = parts[4]
            l_addr, l_port = _split_addr_port(local)
            r_addr, r_port = _split_addr_port(remote)
            entries.append({
                "local_address": l_addr,
                "local_port": l_port,
                "remote_address": r_addr,
                "remote_port": r_port,
                "protocol": "tcp"
            })
        return entries[:50]
    except Exception:
        return []


def _split_addr_port(addr_str):
    addr_str = addr_str.strip()
    if addr_str.startswith("["):
        idx = addr_str.rfind("]")
        return addr_str[1:idx], addr_str[idx+1:].lstrip(":")
    parts = addr_str.rsplit(":", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return addr_str, ""


def _parse_proc_net_tcp(state_hex):
    entries = []
    for proc_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            with open(proc_file, "r") as f:
                for line in f:
                    if "sl" in line and "local_address" in line:
                        continue
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    if parts[3] != state_hex:
                        continue
                    addr, port = _hex_addr_port(parts[1])
                    entries.append({"address": addr, "port": str(port), "protocol": "tcp"})
        except Exception:
            pass
    return entries


def _hex_addr_port(hex_pair):
    addr_hex, port_hex = hex_pair.split(":")
    port = int(port_hex, 16)
    addr_parts = [addr_hex[i:i+2] for i in range(0, 8, 2)]
    return f"{int(addr_parts[3],16)}.{int(addr_parts[2],16)}.{int(addr_parts[1],16)}.{int(addr_parts[0],16)}", port


def _get_recent_connections(threshold):
    entries = []
    try:
        r = subprocess.run(
            "ss -tan state established | grep -v '127.0.0.1\\|::1' | head -30",
            shell=True, capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            l_addr, l_port = _split_addr_port(parts[3])
            r_addr, r_port = _split_addr_port(parts[4])
            if r_addr in ("0.0.0.0", "*", "::"):
                continue
            entries.append({
                "local_address": l_addr,
                "local_port": l_port,
                "remote_address": r_addr,
                "remote_port": r_port,
                "protocol": "tcp"
            })
    except Exception:
        pass
    return entries[:30]


# ── Process Kill ────────────────────────────────────────────────

def kill_process(pid):
    """Kill a process by PID."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=2)
        return {"success": True, "pid": pid, "name": name, "message": f"Process {name} (PID {pid}) killed"}
    except psutil.NoSuchProcess:
        return {"success": False, "pid": pid, "error": "Process not found"}
    except psutil.AccessDenied:
        return {"success": False, "pid": pid, "error": "Access denied (need root)"}
    except Exception as e:
        return {"success": False, "pid": pid, "error": str(e)}


# ── Utility ─────────────────────────────────────────────────────

def _fmt_bytes(bytes_val):
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.1f} GB"
    if bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.1f} MB"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    return f"{bytes_val} B"


def _is_elf_file(path):
    """Check if file starts with ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def _is_upx_packed(path):
    """Check if ELF binary is packed with UPX."""
    try:
        with open(path, "rb") as f:
            f.seek(0)
            content = f.read(4096)
            return b"UPX!" in content or b"UPX0" in content or b"UPX1" in content
    except Exception:
        return False


def _dir_size_fast(path):
    """Get directory size quickly using du."""
    try:
        r = subprocess.run(["du", "-sb", path], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return int(r.stdout.split()[0])
    except Exception:
        pass
    return 0


def _get_system_users():
    """Get list of non-system users (UID >= 1000)."""
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) >= 3:
                    try:
                        uid = int(parts[2])
                        if uid >= 1000 and uid < 65534:
                            users.append(parts[0])
                    except ValueError:
                        pass
    except Exception:
        pass
    return users


def _get_user_crontab(user):
    """Get crontab for a user."""
    try:
        r = subprocess.run(["crontab", "-u", user, "-l"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return ""
