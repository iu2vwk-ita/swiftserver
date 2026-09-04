"""Test minimi ByteSweep: auth, safe_path, health, cleanup. Esegui: pytest -q"""
import sys
sys.path.insert(0, "/home/adivor/swiftserver")
sys.path.insert(0, "/opt/server-monitor/venv/lib/python3.11/site-packages")

import server_monitor as sm


def _client_with_pw():
    sm._runtime_password = None
    sm.app.config["PANEL_PASSWORD"] = sm._hash_password("test123")
    sm._sessions.clear()
    return sm.app.test_client()


def test_health_no_auth():
    c = sm.app.test_client().get("/api/health")
    assert c.status_code == 200
    assert c.get_json()["status"] == "ok"


def test_protected_401_without_token():
    c = _client_with_pw().post("/api/process/kill", json={"pid": 999999})
    assert c.status_code == 401


def test_login_wrong_401():
    c = _client_with_pw().post("/api/auth/login", json={"password": "nope"})
    assert c.status_code == 401


def test_login_ok_200():
    c = _client_with_pw().post("/api/auth/login", json={"password": "test123"})
    assert c.status_code == 200
    assert c.get_json()["success"] is True


def test_safe_path_blocks():
    for p in ("/proc/1", "/sys/kernel", "/dev/sda", "/run/x", "/boot/grub"):
        assert sm._safe_path(p) == "/", p


def test_safe_path_allows():
    assert sm._safe_path("/home/adivor") == "/home/adivor"
    assert sm._safe_path("/etc/../home") == "/home"


def test_cleanup_status_shape():
    import cleanup
    st = cleanup.get_status()
    assert isinstance(st, list) and len(st) >= 5
    assert all({"id", "name"} <= set(x) for x in st)
