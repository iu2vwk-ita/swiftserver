#!/usr/bin/env python3
"""
ByteSweep Auto-Cleanup Agent
Runs periodically to check disk usage and clean when above threshold.
Designed to be run via systemd timer or cron.
"""

import os
import sys
import logging
import json
from datetime import datetime

# Add install dir to path for cleanup import
sys.path.insert(0, "/opt/server-monitor")

import psutil

THRESHOLD = 90  # percent

LOG_DIR = "/opt/server-monitor/logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "cleanup.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("bytesweep.agent")


def check_disk():
    """Return the highest disk usage percentage across all partitions."""
    max_pct = 0
    for p in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(p.mountpoint)
            if usage.percent > max_pct:
                max_pct = usage.percent
        except (OSError, PermissionError):
            pass
    return max_pct


def main():
    disk_pct = check_disk()
    log.info(f"Disk usage: {disk_pct:.1f}% (threshold: {THRESHOLD}%)")

    if disk_pct < THRESHOLD:
        log.info("Below threshold, nothing to do.")
        return 0

    log.warning(f"Disk above {THRESHOLD}%! Running cleanup...")

    try:
        import cleanup
        result = cleanup.run_cleanup()
        log.info(f"Cleanup complete: freed {result['total_freed_str']}")
        for item in result["items"]:
            if item["freed"] > 0:
                log.info(f"  {item['name']}: +{item['freed_str']}")
    except Exception as e:
        log.error(f"Cleanup failed: {e}")
        return 1

    new_pct = check_disk()
    log.info(f"Disk after cleanup: {new_pct:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
