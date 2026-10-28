from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from .config import Config
from .monitor import Monitor
from .policy import evaluate, summarize
from .scanner import build_devices, detect_subnet, read_arp_table
from .store import Store


def cmd_scan(args: argparse.Namespace) -> int:
    config = Config.load()
    config.normalize()
    if not config.subnet:
        subnet, gateway = detect_subnet()
        config.subnet, config.gateway = subnet, config.gateway or gateway

    if args.no_ping:
        devices = build_devices(read_arp_table())
    else:
        store = Store()
        monitor = Monitor(store, config)
        monitor.scan_once()
        devices = store.sorted_devices()

    verdicts = evaluate(devices, config)
    if args.json:
        print(json.dumps({
            "subnet": config.subnet,
            "gateway": config.gateway,
            "devices": [d.to_dict() for d in devices],
            "verdicts": [v.__dict__ for v in verdicts],
            "summary": summarize(verdicts),
        }, indent=2))
        return 0

    print(f"Subnet : {config.subnet or 'unknown'}")
    print(f"Gateway: {config.gateway or 'unknown'}")
    print(f"Devices: {len(devices)}")
    print()
    header = f"{'IP':<16}{'MAC':<19}{'STATE':<7}{'POLICY':<12}{'VENDOR':<24}HOST"
    print(header)
    print("-" * len(header))
    vmap = {v.mac: v for v in verdicts}
    for d in devices:
        v = vmap.get(d.mac)
        print(
            f"{d.ip:<16}{d.mac:<19}{d.state:<7}{(v.action if v else '-'):<12}"
            f"{(d.vendor or '-'):<24}{d.hostname or ''}"
        )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    uvicorn.run(
        "netcut.app:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        reload=args.reload,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcut", description="Home LAN inventory and policy monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="one-off scan and print the table")
    p_scan.add_argument("--json", action="store_true", help="machine-readable output")
    p_scan.add_argument("--no-ping", action="store_true", help="skip ping sweep, read ARP only")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="run the web dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8088)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
