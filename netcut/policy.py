from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .scanner import Device


@dataclass
class Verdict:
    mac: str
    ip: str
    action: str
    reason: str


def evaluate(devices: list[Device], config: Config) -> list[Verdict]:
    """Decide what should happen to each device under the current policy.

    This is a *policy engine*, not an enforcer. It never touches the network;
    it produces the intent that an operator (or a router adapter) applies.
    """
    verdicts: list[Verdict] = []
    allow = set(config.allowlist)
    block = set(config.blocklist)

    for dev in devices:
        mac = dev.mac.lower()
        if mac in block:
            verdicts.append(Verdict(mac, dev.ip, "block", "on blocklist"))
        elif allow and mac not in allow:
            verdicts.append(Verdict(mac, dev.ip, "quarantine", "not on allowlist"))
        elif dev.trusted:
            verdicts.append(Verdict(mac, dev.ip, "allow", "trusted device"))
        elif config.guest_mode and not dev.trusted:
            verdicts.append(Verdict(mac, dev.ip, "throttle", "guest mode active"))
        else:
            verdicts.append(Verdict(mac, dev.ip, "allow", "default policy"))
    return verdicts


def summarize(verdicts: list[Verdict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.action] = counts.get(v.action, 0) + 1
    return counts
