#!/usr/bin/env python3
"""BitSpear — internal assessment & automated penetration agent. Scaffold only."""

from __future__ import annotations

import argparse
import sys


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitSpear (scaffold)

Goal: authorized internal network / host vulnerability assessment and
automated penetration workflows that mimic an actor already inside the perimeter.

Findings feed BitGraph, BitReport, and BitAI (verification / gap fill).
Use only on systems you own or have explicit permission to test.
Not implemented yet.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print("BitSpear 0.0.0 (scaffold)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bitspear",
        description="BitSpear — internal assessment agent (early scaffold).",
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
