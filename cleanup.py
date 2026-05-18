#!/usr/bin/env python3
"""
ByteSweep Cleanup Agent
Disk cleaning operations for server maintenance.
"""

import os
import shutil
import subprocess
import logging
from datetime import datetime

log = logging.getLogger("bytesweep.cleanup")


def _size(path):
    """Get directory size in bytes, returns 0 on failure."""
    try:
        total = 0
        for entry in os.scandir(path):
            try:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += _size(entry.path)
            except (OSError, PermissionError):
                pass
        return total
    except (OSError, PermissionError):
        return 0


def _fmt(bytes_val):
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.1f} GB"
    if bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.1f} MB"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    return f"{bytes_val} B"


def _run(cmd):
    """Run shell command, return (success, output)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return r.returncode == 0, r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        return False, str(e)


# ── Individual cleaners ──────────────────────────────────────────

def clean_apt():
    before = _size("/var/cache/apt") + _size("/var/lib/apt/lists")
    ok1, _ = _run("apt-get clean")
    ok2, _ = _run("apt-get autoclean")
    ok3, _ = _run("apt-get autoremove --purge -y")
    after = _size("/var/cache/apt") + _size("/var/lib/apt/lists")
    freed = max(0, before - after)
    return {"name": "APT Cache", "freed": freed, "freed_str": _fmt(freed),
            "success": ok1 and ok2, "detail": "Removed downloaded packages and orphan deps"}


def clean_journal():
    before = _size("/var/log/journal")
    ok, out = _run("journalctl --vacuum-size=200M")
    after = _size("/var/log/journal")
    freed = max(0, before - after)
    return {"name": "Journal Logs", "freed": freed, "freed_str": _fmt(freed),
            "success": ok, "detail": out[:100] if out else "Retention set to 200MB"}


def clean_snap():
    cache = _size("/var/lib/snapd/cache")
    if cache > 0:
        _run("rm -rf /var/lib/snapd/cache/*")
    # Remove disabled snap revisions
    before = _size("/var/lib/snapd")
    ok, _ = _run("snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' | while read n r; do snap remove \"$n\" --revision=\"$r\" 2>/dev/null; done")
    after = _size("/var/lib/snapd")
    freed = max(0, before - after) + cache
    return {"name": "Snap Packages", "freed": freed, "freed_str": _fmt(freed),
            "success": True, "detail": "Removed old snap revisions and cache"}


def clean_docker():
    before = _size("/var/lib/docker")
    ok, out = _run("docker system prune -a -f 2>/dev/null")
    after = _size("/var/lib/docker")
    freed = max(0, before - after)
    return {"name": "Docker Images", "freed": freed, "freed_str": _fmt(freed),
            "success": True, "detail": out[:100] if out else "No docker cleanup needed"}


def clean_pip():
    before = _size("/root/.cache/pip") + _size(os.path.expanduser("~/.cache/pip"))
    _run("pip cache purge 2>/dev/null")
    _run("sudo pip cache purge 2>/dev/null")
    after = _size("/root/.cache/pip") + _size(os.path.expanduser("~/.cache/pip"))
    freed = max(0, before - after)
    return {"name": "Pip Cache", "freed": freed, "freed_str": _fmt(freed),
            "success": True, "detail": "Purged pip download cache"}


def clean_npm():
    home = os.path.expanduser("~/.npm/_cacache")
    before = _size(home) if os.path.exists(home) else 0
    _run("npm cache clean --force 2>/dev/null")
    after = _size(home) if os.path.exists(home) else 0
    freed = max(0, before - after)
    return {"name": "npm Cache", "freed": freed, "freed_str": _fmt(freed),
            "success": True, "detail": "Cleared npm package cache"}


def clean_browsers():
    """Clean puppeteer/playwright/electron caches."""
    paths = [
        os.path.expanduser("~/.cache/puppeteer"),
        os.path.expanduser("~/.cache/ms-playwright"),
        "/root/.cache/ms-playwright",
        os.path.expanduser("~/.cache/electron"),
    ]
    total = 0
    for p in paths:
        if os.path.exists(p):
            total += _size(p)
            shutil.rmtree(p, ignore_errors=True)
    return {"name": "Browser Caches", "freed": total, "freed_str": _fmt(total),
            "success": True, "detail": "Removed Playwright/Puppeteer/Electron browser downloads"}


def clean_syslogs():
    """Remove rotated syslog files."""
    paths = ["/var/log/syslog.1", "/var/log/syslog.2.gz", "/var/log/syslog.3.gz",
             "/var/log/syslog.4.gz", "/var/log/syslog.5.gz", "/var/log/syslog.6.gz",
             "/var/log/syslog.7.gz"]
    total = 0
    for p in paths:
        try:
            total += os.path.getsize(p)
            os.remove(p)
        except OSError:
            pass
    return {"name": "Old Syslogs", "freed": total, "freed_str": _fmt(total),
            "success": True, "detail": "Removed rotated syslog files"}


def clean_tmp():
    """Clean /tmp files older than 1 day."""
    before = _size("/tmp")
    _run("find /tmp -type f -atime +1 -delete 2>/dev/null")
    _run("find /tmp -type d -empty -atime +1 -delete 2>/dev/null")
    after = _size("/tmp")
    freed = max(0, before - after)
    return {"name": "Temp Files", "freed": freed, "freed_str": _fmt(freed),
            "success": True, "detail": "Removed /tmp files older than 1 day"}


def clean_uv():
    path = os.path.expanduser("~/.cache/uv")
    before = _size(path) if os.path.exists(path) else 0
    shutil.rmtree(path, ignore_errors=True)
    return {"name": "UV Python Cache", "freed": before, "freed_str": _fmt(before),
            "success": True, "detail": "Removed uv package manager cache"}


# ── Registry ────────────────────────────────────────────────────

CLEANERS = [
    ("apt",       "APT Cache",         clean_apt,       "Removes downloaded packages and orphan dependencies"),
    ("journal",   "Journal Logs",      clean_journal,   "Limits systemd journal retention to 200MB"),
    ("syslogs",   "Old Syslogs",       clean_syslogs,   "Removes rotated /var/log/syslog archives"),
    ("snap",      "Snap Packages",      clean_snap,      "Removes old snap revisions and download cache"),
    ("docker",    "Docker Images",     clean_docker,    "Removes unused Docker images and containers"),
    ("pip",       "Pip Cache",         clean_pip,       "Purges Python pip download cache"),
    ("npm",       "npm Cache",         clean_npm,       "Clears Node.js npm package cache"),
    ("browsers",  "Browser Caches",    clean_browsers,  "Removes Playwright/Puppeteer/Electron browser downloads"),
    ("tmp",       "Temp Files",        clean_tmp,       "Deletes /tmp files older than 1 day"),
    ("uv",        "UV Cache",          clean_uv,        "Removes UV Python package manager cache"),
]


# ── Public API ───────────────────────────────────────────────────

def get_status():
    """Return list of all cleanable items with estimated sizes."""
    items = []
    for key, name, func, desc in CLEANERS:
        items.append({
            "id": key,
            "name": name,
            "description": desc,
        })
    return items


def run_cleanup(items=None):
    """
    Run cleanup operations. If items is None, run all.
    Returns list of results.
    """
    results = []
    total_freed = 0

    to_run = CLEANERS
    if items:
        to_run = [(k, n, f, d) for k, n, f, d in CLEANERS if k in items]

    for key, name, func, desc in to_run:
        try:
            r = func()
            r["id"] = key
            r["name"] = name
            r["description"] = desc
            total_freed += r["freed"]
            results.append(r)
            log.info(f"cleanup.{key}: freed {r['freed_str']}")
        except Exception as e:
            log.error(f"cleanup.{key} failed: {e}")
            results.append({
                "id": key, "name": name,
                "freed": 0, "freed_str": "0 B",
                "success": False, "detail": str(e),
                "description": desc,
            })

    return {
        "timestamp": datetime.now().isoformat(),
        "total_freed": total_freed,
        "total_freed_str": _fmt(total_freed),
        "items": results,
    }
