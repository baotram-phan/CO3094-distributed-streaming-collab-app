"""Run real-socket 10/20-client scalability test and save machine-readable evidence.

Example: python -m scripts.run_scalability --output reports/scalability.json
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys

from tests.load_20_clients import run_scalability_scenario


def main() -> int:
    parser = argparse.ArgumentParser(description="10/20 concurrent ONLINE clients via TLS + Reliable UDP")
    parser.add_argument("--clients", nargs="+", type=int, choices=(10, 20),
                        default=[10, 20])
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of simultaneous login workers; default up to 8")
    parser.add_argument("--output", type=Path, default=Path("reports/scalability_10_20.json"))
    args = parser.parse_args()
    report = {
        "scenario": "real TLS bootstrap + encrypted UDP REGISTER/AUTH + direct/broadcast chat",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "network": "loopback 127.0.0.1 (NOT LAN)",
        "packet_loss": "not injected",
        "results": [],
    }
    try:
        for count in args.clients:
            result = run_scalability_scenario(
                count, login_workers=args.workers,
                idle_seconds=11.5 if count == 20 else 0.0,
            )
            report["results"].append(result.to_dict())
    except Exception as exc:
        print(f"[SCALABILITY] FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(f"[SCALABILITY] PASS; report saved to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
