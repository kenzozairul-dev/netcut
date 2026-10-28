from __future__ import annotations

import threading
import time
from typing import Any

from .config import Config
from .scanner import (
    build_devices,
    detect_subnet,
    ping_sweep,
    read_arp_table,
    resolve_hostname,
)
from .store import Store


class Monitor:
    """Background scanner that keeps the Store up to date."""

    def __init__(self, store: Store, config: Config) -> None:
        self.store = store
        self.config = config
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_scan: float | None = None
        self.last_error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netcut-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                self.last_error = str(exc)
            self._stop.wait(self.config.scan_interval_seconds)

    def scan_once(self) -> dict[str, Any]:
        subnet = self.config.subnet
        gateway = self.config.gateway
        if not subnet:
            subnet, detected_gateway = detect_subnet()
            gateway = gateway or detected_gateway
            self.config.subnet = subnet
            self.config.gateway = gateway

        if subnet:
            ping_sweep(
                subnet,
                timeout_ms=self.config.ping_timeout_ms,
                concurrency=self.config.ping_concurrency,
            )

        devices = build_devices(read_arp_table())
        for dev in devices:
            if dev.ip == gateway:
                dev.hostname = "gateway"
            else:
                dev.hostname = resolve_hostname(dev.ip)

        result = self.store.upsert_scan(devices)
        self.last_scan = time.time()
        self.last_error = None
        return result
