#!/usr/bin/env python3
"""BitCannon — external technical attack simulation. Scaffold only."""

from __future__ import annotations

import argparse
import sys


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitCannon (scaffold)

Goal: simulate an external attacker outside the LAN — recon through exploitation
of technical vulnerabilities only (no phishing / social engineering).

Pairs with BitScope for exposure truth and BitIntel for exploit context.
Use only against authorized external targets.
Not implemented yet.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print("BitCannon 0.0.0 (scaffold)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bitcannon",
        description="BitCannon — external attack simulation (early scaffold).",
    )
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("info", help="Product overview")
    i.set_defaults(func=cmd_info)
    v = sub.add_parser("version", help="Scaffold version")
    v.set_defaults(func=cmd_version)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
