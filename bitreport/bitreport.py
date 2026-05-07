#!/usr/bin/env python3
"""
BitReport — unified reporting across the BitSentry suite.

Aggregates BitProbe (and optional BitScope) outputs into one JSON + PDF +
interactive dashboard. Per-product reports remain; this is the grand-scale view.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure local imports resolve when run as script (bitreport modules + repo root for products)
_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _ROOT.parent
for _p in (_ROOT, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from products import SUITE_VERSION  # noqa: E402
from suite_build import run_build  # noqa: E402
from suite_schema import BITREPORT_SCHEMA_VERSION  # noqa: E402


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitReport — unified suite reporting (MVP)

Consumes:
  • One or more BitProbe *.json scan reports
  • Optional BitScope discovery JSON (--bitscope)

Produces (per build):
  • Master JSON — full suite object (includes raw_embed for drill-down)
  • PDF — executive summary + severity rollups + findings table
  • Dashboard — React SPA (Vite) with charts + searchable findings table

Example:
  python bitreport.py build -o ./suite_out \\
      --bitprobe ../bitprobe/scan_results/a.json \\
      --bitscope ../bitscope_out.json \\
      --formats json,pdf,dashboard

Dashboard requires Node once:  cd bitreport/dashboard && npm ci && npm run build
Or pass --try-npm to let `build` attempt npm ci && npm run build automatically.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(
        f"BitReport (BitSentry suite {SUITE_VERSION}, schema {BITREPORT_SCHEMA_VERSION})"
    )
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    output_dir = Path(args.output).resolve()
    bitprobe = [Path(p).resolve() for p in (args.bitprobe or [])]
    bitscope = Path(args.bitscope).resolve() if args.bitscope else None

    inc_raw = [x.strip().lower() for x in args.include.split(",") if x.strip()]
    inc_set = set(inc_raw if inc_raw else ["bitprobe", "bitscope"])

    fmt_raw = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    formats = frozenset(fmt_raw if fmt_raw else ["json", "pdf", "dashboard"])

    invalid = formats - {"json", "pdf", "dashboard"}
    if invalid:
        print(f"[!] Unknown format(s): {', '.join(invalid)}", file=sys.stderr)
        return 1

    if "bitprobe" in inc_set and not bitprobe:
        print("[*] No --bitprobe files; excluding bitprobe from this build.", file=sys.stderr)
        inc_set.discard("bitprobe")
    if "bitscope" in inc_set and not bitscope:
        print("[*] No --bitscope; excluding bitscope from this build.", file=sys.stderr)
        inc_set.discard("bitscope")

    if not inc_set:
        print("[!] Nothing left to include after resolving inputs.", file=sys.stderr)
        return 1

    include = frozenset(inc_set)

    name = args.name.strip() or "bitsentry_suite_report"
    title = args.title.strip() or "BitSentry Unified Security Report"

    dashboard_src = (_ROOT / "dashboard").resolve()

    msgs, errs = run_build(
        output_dir=output_dir,
        base_name=name,
        title=title,
        bitprobe_paths=bitprobe,
        bitscope_path=bitscope,
        include=include,
        formats=formats,
        dashboard_src=dashboard_src,
        try_npm_build=args.try_npm,
    )

    for m in msgs:
        print(m)
    for e in errs:
        print(f"[!] {e}", file=sys.stderr)

    return 1 if errs else 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bitreport",
        description="BitReport — suite-level JSON, PDF, and HTML dashboard.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("info", help="Overview and examples")
    i.set_defaults(func=cmd_info)

    v = sub.add_parser("version", help="Version")
    v.set_defaults(func=cmd_version)

    b = sub.add_parser("build", help="Aggregate sources and write artifacts")
    b.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output directory for suite_report files + dashboard/",
    )
    b.add_argument(
        "--bitprobe",
        action="append",
        help="Path to BitProbe JSON (repeatable)",
    )
    b.add_argument("--bitscope", help="Path to BitScope discovery JSON")
    b.add_argument(
        "--include",
        default="bitprobe,bitscope",
        help="Comma list: bitprobe, bitscope (default both if inputs present)",
    )
    b.add_argument(
        "--formats",
        default="json,pdf,dashboard",
        help="Comma list: json, pdf, dashboard",
    )
    b.add_argument(
        "--name",
        default="bitsentry_suite_report",
        help="Base filename without extension",
    )
    b.add_argument(
        "--title",
        default="BitSentry Unified Security Report",
        help="Report title shown in PDF/dashboard",
    )
    b.add_argument(
        "--try-npm",
        action="store_true",
        help="If dashboard/dist is missing, run npm ci && npm run build in dashboard/",
    )
    b.set_defaults(func=cmd_build)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
