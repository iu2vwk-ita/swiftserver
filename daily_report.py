"""Report giornaliero ByteSweep: colleziona metriche tutto il giorno e genera il riepilogo serale."""
from __future__ import annotations
import os, json, time, datetime
import psutil

STATE_DIR = "/opt/server-monitor/logs"
DAILY_FILE = os.path.join(STATE_DIR, "daily_state.json")
LOG_DIR = "/opt/server-monitor/logs"

NOTIFY_MAP = {"cleanup_done": "🧹 Pulizia", "cleanup_error": "⚠️ Pulizia fallita",
              "scan_done": "🔍 Scan sicurezza", "security_alert": "🛡️ Allerta sicurezza"}


def _now():
    return datetime.datetime.now()


def _load():
    try:
        with open(DAILY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(d):
    try:
        os.makedirs(os.path.dirname(DAILY_FILE), exist_ok=True)
        with open(DAILY_FILE, "w") as f:
            json.dump(d, f, indent=2)
    except Exception:
        pass


def _new_day():
    """Reset stato giornaliero (di default alle 04:00 per stare dentro la giornata)."""
    return {
        "date": _now().strftime("%Y-%m-%d"),
        "samples": {"cpu": [], "ram": [], "load": [], "temp": [], "net_rx": [], "net_tx": []},
        "jobs": [],
        "start_bytes": None,
    }


def reset_if_new_day():
    d = _load()
    today = _now().strftime("%Y-%m-%d")
    if d.get("date") != today:
        d = _new_day()
        # memorizza baseline byte per il traffico della giornata
        net = psutil.net_io_counters()
        d["start_bytes"] = {"rx": net.bytes_recv, "tx": net.bytes_sent}
        _save(d)
    return d


def sample():
    """Chiamato periodicamente: accumula un campione di metriche."""
    d = reset_if_new_day()
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    load = psutil.getloadavg()
    temp = None
    try:
        for entry in psutil.sensors_temperatures():
            for s in entry:
                if s.current is not None:
                    temp = temp or s.current
    except Exception:
        pass
    net = psutil.net_io_counters()
    d["samples"]["cpu"].append(cpu)
    d["samples"]["ram"].append(mem.percent)
    d["samples"]["load"].append(load[0])
    if temp:
        d["samples"]["temp"].append(temp)
    d["samples"]["net_rx"].append(net.bytes_recv)
    d["samples"]["net_tx"].append(net.bytes_sent)
    # max 500 campioni per evitare crescita illimitata (~ogni 5 min = 288/giorno)
    for k in d["samples"]:
        if len(d["samples"][k]) > 500:
            d["samples"][k] = d["samples"][k][-500:]
    d["_last_ts"] = time.time()
    _save(d)


def record_job(kind, detail=""):
    """Registra un lavoro eseguito (pulizia, scan, backup)."""
    d = reset_if_new_day()
    d["jobs"].append({"ts": _now().isoformat(), "kind": kind, "detail": detail})
    if len(d["jobs"]) > 200:
        d["jobs"] = d["jobs"][-200:]
    _save(d)


def _avg(lst):
    return sum(lst) / len(lst) if lst else 0


def _fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if b < 100 else f"{b:.0f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def build_report():
    """Genera il testo del report giornaliero."""
    d = reset_if_new_day()
    s = d["samples"]

    # Uptime
    up = psutil.boot_time()
    now = time.time()
    up_sec = now - up
    up_h = up_sec / 3600
    up_pct = 100 * (up_sec / 86400) if up_sec < 86400 else 100

    lines = [f"📊 <b>Report server — {d['date']}</b>", ""]
    lines.append(f"⏱️ Accesso: {up_h:.1f}h ({up_pct:.1f}% di oggi)")

    if s["cpu"]:
        lines.append(f"⚙️ CPU: media <b>{_avg(s['cpu']):.0f}%</b>, picco <b>{max(s['cpu']):.0f}%</b>")
    if s["ram"]:
        mem = psutil.virtual_memory()
        lines.append(f"💾 RAM: media <b>{_avg(s['ram']):.0f}%</b> ({mem.total/2**30:.1f}GB totali), picco <b>{max(s['ram']):.0f}%</b>")
    if s["load"]:
        lines.append(f"📈 Carico: media <b>{_avg(s['load']):.2f}</b>, max <b>{max(s['load']):.2f}</b>")
    if s["temp"]:
        lines.append(f"🌡️ Temp max: <b>{max(s['temp']):.0f}°C</b>")

    # Traffico
    net_now = psutil.net_io_counters()
    start = d.get("start_bytes") or {"rx": net_now.bytes_recv, "tx": net_now.bytes_sent}
    rx = net_now.bytes_recv - start["rx"]
    tx = net_now.bytes_sent - start["tx"]
    lines.append(f"📡 Traffico: ↓ <b>{_fmt_bytes(rx)}</b> ↑ <b>{_fmt_bytes(tx)}</b>")

    # Lavori
    jobs = d["jobs"]
    if jobs:
        lines.append("")
        lines.append(f"🧹 <b>Lavori oggi ({len(jobs)}):</b>")
        for j in jobs[-10:]:
            label = NOTIFY_MAP.get(j["kind"], j["kind"])
            lines.append(f"• {label} {j['detail']}")
    else:
        lines.append("")
        lines.append("🧹 Nessun lavoro eseguito oggi.")

    # OpenCode
    oc = opencode_summary()
    lines.append("")
    lines.append("🤖 <b>OpenCode:</b> " + oc)

    return "\n".join(lines)


def opencode_summary():
    """Elenca TUTTE le sessioni opencode del giorno con il lavoro svolto."""
    log_root = os.path.expanduser("~/.local/share/opencode/log")
    today = _now().strftime("%Y-%m-%d")
    sessions = []
    try:
        files = []
        for fn in os.listdir(log_root):
            if not fn.endswith(".log"):
                continue
            # sessione odierna: nome file inizia con la data odierna
            if not fn.startswith(today):
                continue
            p = os.path.join(log_root, fn)
            try:
                with open(p, "r", errors="ignore") as f:
                    txt = f.read(200000)  # limito per performance
            except Exception:
                continue
            # orario dal nome: YYYY-MM-DDTHHMMSS.log
            ts = fn.replace(".log", "")
            hh = ts[11:13] if len(ts) >= 13 else "?"
            mm = ts[13:15] if len(ts) >= 15 else "?"
            # operazioni eseguite (best-effort)
            n_edit = txt.count('"edit"') + txt.count("type=edit") + txt.count("tool=edit")
            n_write = txt.count('"write"') + txt.count("tool=write")
            n_bash = txt.count('"bash"') + txt.count("tool=bash") + txt.count("command=")
            size = os.path.getsize(p)
            sessions.append({"time": f"{hh}:{mm}", "edit": n_edit, "write": n_write,
                             "bash": n_bash, "size": size})
    except Exception as e:
        return f"nessun log (err {e})"
    sessions.sort(key=lambda s: s["time"])
    if not sessions:
        return "0 sessioni oggi"
    lines = [f"{len(sessions)} sessioni:"]
    for s in sessions:
        ops = s["edit"] + s["write"] + s["bash"]
        lines.append(f"• {s['time']} — {ops} operazioni ({s['edit']} edit, {s['write']} write, {s['bash']} bash)")
    return "\n".join(lines)


async def send_daily_report(bot_url):
    """Invia il report via Telegram (usa advanced.notify)."""
    import advanced
    report = build_report()
    advanced.notify("temp_warn", report)  # riusa il canale sempre-attivo
