from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .config import data_dir
from .scanner import Device, normalize_mac


class Store:
    """JSON-backed device inventory with a small event log."""

    def __init__(self, directory: Path | None = None, max_events: int = 500) -> None:
        self.dir = Path(directory) if directory else data_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.devices_path = self.dir / "devices.json"
        self.events_path = self.dir / "events.json"
        self.max_events = max_events
        self._lock = threading.RLock()
        self.devices: dict[str, Device] = {}
        self.events: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if self.devices_path.exists():
            raw = json.loads(self.devices_path.read_text(encoding="utf-8"))
            for item in raw:
                dev = Device(**item)
                self.devices[dev.mac] = dev
        if self.events_path.exists():
            try:
                self.events = json.loads(self.events_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.events = []

    def _flush(self) -> None:
        payload = [d.to_dict() for d in self.sorted_devices()]
        self.devices_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.events_path.write_text(
            json.dumps(self.events[-self.max_events :], indent=2), encoding="utf-8"
        )

    def sorted_devices(self) -> list[Device]:
        return sorted(self.devices.values(), key=lambda d: tuple(int(p) for p in d.ip.split(".")))

    def get(self, mac: str) -> Device | None:
        return self.devices.get(normalize_mac(mac))

    def upsert_scan(self, found: list[Device]) -> dict[str, Any]:
        now = time.time()
        new_devices: list[Device] = []
        with self._lock:
            seen_macs = {d.mac for d in found}
            for dev in found:
                existing = self.devices.get(dev.mac)
                if existing is None:
                    dev.first_seen = now
                    dev.last_seen = now
                    self.devices[dev.mac] = dev
                    new_devices.append(dev)
                    self.log("device_new", f"New device {dev.ip} ({dev.mac})", dev.mac)
                else:
                    if existing.ip != dev.ip:
                        self.log(
                            "device_ip_change",
                            f"{dev.mac} moved {existing.ip} -> {dev.ip}",
                            dev.mac,
                        )
                    existing.ip = dev.ip
                    existing.vendor = dev.vendor or existing.vendor
                    existing.hostname = dev.hostname or existing.hostname
                    existing.state = "up"
                    existing.last_seen = now
            for mac, dev in self.devices.items():
                if mac not in seen_macs:
                    dev.state = "down"
            self._flush()
        return {"new": [d.to_dict() for d in new_devices], "total": len(self.devices)}

    def set_trusted(self, mac: str, trusted: bool) -> Device | None:
        with self._lock:
            dev = self.get(mac)
            if not dev:
                return None
            dev.trusted = trusted
            self.log("trust", f"{dev.ip} trusted={trusted}", dev.mac)
            self._flush()
            return dev

    def set_blocked(self, mac: str, blocked: bool) -> Device | None:
        with self._lock:
            dev = self.get(mac)
            if not dev:
                return None
            dev.blocked = blocked
            self.log("block", f"{dev.ip} blocked={blocked}", dev.mac)
            self._flush()
            return dev

    def log(self, kind: str, message: str, mac: str | None = None) -> None:
        self.events.append(
            {"ts": time.time(), "kind": kind, "message": message, "mac": mac}
        )
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(reversed(self.events[-limit:]))
