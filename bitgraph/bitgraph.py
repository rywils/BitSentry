#!/usr/bin/env python3
"""BitGraph — attack path analysis. Scaffold only."""

from __future__ import annotations

import argparse
import sys


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitGraph (scaffold)

Goal: model attack paths — how exposed assets, identities, and weaknesses chain
together (blast radius, lateral movement options, choke points).

Will consume outputs from BitScope, BitProbe, BitSpear, BitCannon, and BitWatch.
Not implemented yet.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print("BitGraph 0.0.0 (scaffold)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bitgraph",
        description="BitGraph — attack path analysis (early scaffold).",
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
