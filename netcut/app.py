from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Config
from .monitor import Monitor
from .policy import evaluate, summarize
from .scanner import detect_subnet, normalize_mac
from .store import Store

WEB_DIR = Path(__file__).resolve().parent / "web"

_config = Config.load()
_config.normalize()
_store = Store()
_monitor = Monitor(_store, _config)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _monitor.start()
    try:
        yield
    finally:
        _monitor.stop()


app = FastAPI(title="NetCut", version=__version__, lifespan=lifespan)


class PolicyUpdate(BaseModel):
    allowlist: list[str] | None = None
    blocklist: list[str] | None = None
    alert_on_new_device: bool | None = None
    guest_mode: bool | None = None
    scan_interval_seconds: int | None = Field(default=None, ge=10, le=3600)


class TrustUpdate(BaseModel):
    trusted: bool


class BlockUpdate(BaseModel):
    blocked: bool


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "version": __version__,
        "monitor_running": _monitor.running,
        "last_scan": _monitor.last_scan,
        "last_error": _monitor.last_error,
        "subnet": _config.subnet,
        "gateway": _config.gateway,
    }


@app.get("/api/devices")
def list_devices() -> dict[str, Any]:
    devices = [d.to_dict() for d in _store.sorted_devices()]
    verdicts = evaluate(_store.sorted_devices(), _config)
    return {
        "devices": devices,
        "policy": {
            "verdicts": [v.__dict__ for v in verdicts],
            "summary": summarize(verdicts),
        },
    }


@app.get("/api/events")
def events(limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    return {"events": _store.recent_events(limit)}


@app.post("/api/scan")
def scan() -> dict[str, Any]:
    result = _monitor.scan_once()
    return {"ok": True, **result}


@app.get("/api/policy")
def get_policy() -> dict[str, Any]:
    return {
        "allowlist": _config.allowlist,
        "blocklist": _config.blocklist,
        "alert_on_new_device": _config.alert_on_new_device,
        "guest_mode": _config.guest_mode,
        "scan_interval_seconds": _config.scan_interval_seconds,
    }


@app.put("/api/policy")
def update_policy(update: PolicyUpdate) -> dict[str, Any]:
    data = update.model_dump(exclude_none=True)
    if "allowlist" in data:
        _config.allowlist = [normalize_mac(m) for m in data["allowlist"] if normalize_mac(m)]
    if "blocklist" in data:
        _config.blocklist = [normalize_mac(m) for m in data["blocklist"] if normalize_mac(m)]
    if "alert_on_new_device" in data:
        _config.alert_on_new_device = bool(data["alert_on_new_device"])
    if "guest_mode" in data:
        _config.guest_mode = bool(data["guest_mode"])
    if "scan_interval_seconds" in data:
        _config.scan_interval_seconds = int(data["scan_interval_seconds"])
    _config.normalize()
    _config.save()
    return get_policy()


@app.post("/api/devices/{mac}/trust")
def trust(mac: str, update: TrustUpdate) -> JSONResponse:
    dev = _store.set_trusted(mac, update.trusted)
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    return JSONResponse(dev.to_dict())


@app.post("/api/devices/{mac}/block")
def block(mac: str, update: BlockUpdate) -> JSONResponse:
    dev = _store.set_blocked(mac, update.blocked)
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    if update.blocked:
        if dev.mac not in _config.blocklist:
            _config.blocklist.append(dev.mac)
    else:
        _config.blocklist = [m for m in _config.blocklist if m != dev.mac]
    _config.normalize()
    _config.save()
    return JSONResponse(dev.to_dict())


@app.get("/api/network")
def network() -> dict[str, Any]:
    subnet, gateway = detect_subnet()
    return {"detected_subnet": subnet, "detected_gateway": gateway, "config": {
        "subnet": _config.subnet,
        "gateway": _config.gateway,
    }}


@app.get("/api/export")
def export() -> JSONResponse:
    payload = {
        "version": __version__,
        "config": get_policy(),
        "devices": [d.to_dict() for d in _store.sorted_devices()],
        "events": _store.recent_events(500),
    }
    return JSONResponse(payload)
