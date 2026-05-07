#!/usr/bin/env python3
"""BitWatch — continuous monitoring (web, internal, cloud). Scaffold only."""

from __future__ import annotations

import argparse
import sys


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitWatch (scaffold)

Goal: continuous visibility across:
  • Web properties (availability, TLS, drift vs last scan)
  • Internal network (segments you authorize)
  • Cloud control planes and exposed services

Integrations will feed BitReport / BitAI. Not implemented yet.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print("BitWatch 0.0.0 (scaffold)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bitwatch",
        description="BitWatch — continuous monitoring (early scaffold).",
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
