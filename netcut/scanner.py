from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Iterable


OUI_VENDORS: dict[str, str] = {
    "00:1a:2b": "Hon Hai / Foxconn",
    "00:1b:63": "Apple",
    "00:1e:c2": "Apple",
    "00:25:00": "Apple",
    "3c:07:54": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    "7c:f1:7e": "TP-Link",
    "50:c7:bf": "TP-Link",
    "a8:93:4a": "Samsung",
    "58:02:05": "Samsung",
    "b2:2c:63": "Private (randomised MAC)",
    "10:71:b3": "Zyxel",
    "18:c0:4d": "Gigabyte",
    "ac:a7:f1": "Intel",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue",
    "44:65:0d": "Amazon",
    "68:37:e9": "Amazon",
    "34:d2:70": "Xiaomi",
    "64:09:80": "Xiaomi",
    "9c:8e:99": "Google",
    "f4:f5:d8": "Google",
    "30:fd:38": "Google",
    "00:9e:c8": "Xiaomi",
}


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str | None = None
    vendor: str | None = None
    state: str = "up"
    first_seen: float | None = None
    last_seen: float | None = None
    trusted: bool = False
    blocked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def lookup_vendor(mac: str) -> str | None:
    mac = normalize_mac(mac)
    if not mac:
        return None
    prefix = mac[:8]
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    second = int(mac.split(":")[0], 16)
    if second & 0x02:
        return "Private (randomised MAC)"
    return None


def parse_arp_table(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        ip, mac = parts[0], parts[1]
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_multicast or addr.is_unspecified or str(addr).endswith(".255"):
            continue
        normalized = normalize_mac(mac)
        if not normalized:
            continue
        if normalized == "ff:ff:ff:ff:ff:ff":
            continue
        rows.append((ip, normalized))
    return rows


def read_arp_table() -> list[tuple[str, str]]:
    if sys.platform.startswith("win"):
        cmd = ["arp", "-a"]
    else:
        cmd = ["arp", "-an"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_arp_table(out)


def detect_subnet() -> tuple[str | None, str | None]:
    """Best-effort local IPv4 subnet and gateway detection."""
    ip: str | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        ip = None

    gateway: str | None = None
    if sys.platform.startswith("win"):
        try:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=20, check=False
            ).stdout
            for line in out.splitlines():
                if "Default Gateway" in line or "Gateway" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match and match.group(1) != "0.0.0.0":
                        gateway = match.group(1)
                        break
        except (OSError, subprocess.SubprocessError):
            pass

    if not ip:
        return None, gateway
    iface = ipaddress.IPv4Interface(f"{ip}/24")
    return str(iface.network), gateway or str(iface.network.network_address + 1)


def _ping(ip: str, timeout_ms: int) -> bool:
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(2, timeout_ms // 1000 + 2),
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ping_sweep(
    subnet: str, timeout_ms: int = 700, concurrency: int = 64
) -> list[str]:
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        for ip, ok in zip(hosts, pool.map(lambda h: _ping(h, timeout_ms), hosts)):
            if ok:
                alive.append(ip)
    return alive


def resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


def build_devices(rows: Iterable[tuple[str, str]]) -> list[Device]:
    devices: list[Device] = []
    for ip, mac in rows:
        devices.append(
            Device(ip=ip, mac=mac, vendor=lookup_vendor(mac), hostname=None)
        )
    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices
