from __future__ import annotations

import json

from fastapi.testclient import TestClient

from netcut.app import app
from netcut.config import Config
from netcut.policy import evaluate, summarize
from netcut.scanner import Device, lookup_vendor, normalize_mac, parse_arp_table
from netcut.store import Store


def test_normalize_mac_variants():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("nope") == ""


def test_lookup_vendor_known_and_random():
    assert lookup_vendor("7c:f1:7e:00:11:22") == "TP-Link"
    assert lookup_vendor("b2:2c:63:85:79:b3") == "Private (randomised MAC)"
    assert lookup_vendor("00:00:00:00:00:01") is None


def test_parse_arp_table_windows_style():
    text = """
Interface: 192.168.0.124 --- 0x10
  Internet Address      Physical Address      Type
  192.168.0.1           10-71-b3-2f-73-30     dynamic
  192.168.0.30          7c-f1-7e-f4-98-16     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
"""
    rows = parse_arp_table(text)
    assert ("192.168.0.1", "10:71:b3:2f:73:30") in rows
    assert len(rows) == 2


def test_policy_allowlist_and_blocklist():
    cfg = Config(allowlist=["aa:bb:cc:dd:ee:ff"], blocklist=["11:22:33:44:55:66"])
    devices = [
        Device(ip="192.168.0.10", mac="aa:bb:cc:dd:ee:ff", trusted=True),
        Device(ip="192.168.0.11", mac="11:22:33:44:55:66"),
        Device(ip="192.168.0.12", mac="de:ad:be:ef:00:01"),
    ]
    verdicts = {v.mac: v.action for v in evaluate(devices, cfg)}
    assert verdicts["aa:bb:cc:dd:ee:ff"] == "allow"
    assert verdicts["11:22:33:44:55:66"] == "block"
    assert verdicts["de:ad:be:ef:00:01"] == "quarantine"


def test_policy_guest_mode_throttles_untrusted():
    cfg = Config(guest_mode=True)
    devices = [
        Device(ip="192.168.0.10", mac="aa:bb:cc:dd:ee:ff", trusted=True),
        Device(ip="192.168.0.11", mac="11:22:33:44:55:66", trusted=False),
    ]
    summary = summarize(evaluate(devices, cfg))
    assert summary == {"allow": 1, "throttle": 1}


def test_store_upsert_and_events(tmp_path):
    store = Store(directory=tmp_path)
    result = store.upsert_scan([Device(ip="192.168.0.20", mac="aa:bb:cc:00:11:22")])
    assert len(result["new"]) == 1
    assert store.get("AA:BB:CC:00:11:22") is not None

    store.upsert_scan([Device(ip="192.168.0.21", mac="aa:bb:cc:00:11:22")])
    kinds = [e["kind"] for e in store.recent_events()]
    assert "device_new" in kinds and "device_ip_change" in kinds

    store.upsert_scan([])
    assert store.get("aa:bb:cc:00:11:22").state == "down"


def test_api_health_and_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("NETCUT_DATA_DIR", str(tmp_path))
    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert health["ok"] is True

        resp = client.put("/api/policy", json={"guest_mode": True, "scan_interval_seconds": 30})
        assert resp.status_code == 200
        body = resp.json()
        assert body["guest_mode"] is True
        assert body["scan_interval_seconds"] == 30

        client.put("/api/policy", json={"guest_mode": False, "scan_interval_seconds": 60})


def test_api_export_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("NETCUT_DATA_DIR", str(tmp_path))
    with TestClient(app) as client:
        payload = client.get("/api/export").json()
        assert set(payload) == {"version", "config", "devices", "events"}
        json.dumps(payload)
