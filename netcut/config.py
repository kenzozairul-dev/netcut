from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "subnet": None,
    "gateway": None,
    "scan_interval_seconds": 60,
    "ping_timeout_ms": 700,
    "ping_concurrency": 64,
    "allowlist": [],
    "blocklist": [],
    "alert_on_new_device": True,
    "guest_mode": False,
}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@dataclass
class Config:
    subnet: str | None = None
    gateway: str | None = None
    scan_interval_seconds: int = 60
    ping_timeout_ms: int = 700
    ping_concurrency: int = 64
    allowlist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    alert_on_new_device: bool = True
    guest_mode: bool = False

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        path = Path(path) if path else _project_root() / "config.json"
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        merged = {**DEFAULT_CONFIG, **raw}
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in merged.items() if k in known})

    def save(self, path: str | Path | None = None) -> Path:
        path = Path(path) if path else _project_root() / "config.json"
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path

    def normalize(self) -> None:
        self.allowlist = sorted({m.strip().lower() for m in self.allowlist if m.strip()})
        self.blocklist = sorted({m.strip().lower() for m in self.blocklist if m.strip()})
        if self.scan_interval_seconds < 10:
            self.scan_interval_seconds = 10
        self.ping_concurrency = max(1, min(self.ping_concurrency, 256))


def data_dir() -> Path:
    override = os.environ.get("NETCUT_DATA_DIR")
    path = Path(override) if override else _project_root() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path
