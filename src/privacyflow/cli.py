from __future__ import annotations
import argparse
import json
import sys
from .config import ConfigError, load_config, rotation_plan

def main() -> int:
    parser = argparse.ArgumentParser(prog="privacyflow", description="Privacyflow profile validation and safe rotation planning")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "rotation-plan"):
        cmd = sub.add_parser(name)
        cmd.add_argument("config", help="Path to Privacyflow TOML config")
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
        if args.command == "validate":
            print(f"Valid configuration: {len(cfg.profiles)} WireGuard profile(s); kill-switch requirement declared.")
            print("Validation only: Privacyflow does not install or enforce a live kill switch in this release.")
        else:
            print(json.dumps({"mode": "DRY_RUN_ONLY", "steps": rotation_plan(cfg)}, indent=2))
            print("No network interfaces or routes were changed.", file=sys.stderr)
        return 0
    except ConfigError as exc:
        print(f"privacyflow: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
