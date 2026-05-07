#!/usr/bin/env python3
"""
BitAI — orchestration across the BitSentry suite.

Monitors suite health, runs checks other products omit, integrates third-party
tools, and verifies accuracy of consolidated reporting (with BitReport).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Repo root (parent of bitai/)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from products import SUITE_VERSION, format_suite_overview  # noqa: E402


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """BitAI — verification today; broader orchestration on the roadmap

Implemented:
  • verify   Structural checks on BitProbe scan JSON or BitReport unified suite JSON
  • suite    Same overview as `bitsentry products`
  • version  Suite version string

Roadmap (suite-wide):
  • Monitor orchestration across BitProbe, BitScope, BitWatch, BitGraph,
    BitIntel, BitReport, BitSpear, and BitCannon
  • Policy hooks and gap-oriented probes; third-party scanner integration
  • Deeper cross-checks feeding BitReport accuracy

Subcommands:
  info       This text
  version    Suite version
  suite      Print full product suite overview (same as `bitsentry products`)
  verify     Sanity-check BitProbe or BitReport (unified suite) JSON
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"BitAI (BitSentry {SUITE_VERSION}) — verify + suite; see bitai info")
    return 0


def cmd_suite(_: argparse.Namespace) -> int:
    print(format_suite_overview())
    return 0


def _severity_bucket(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.lower() in (
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "none",
    )


def _verify_suite_json(data: dict[str, Any], path: Path) -> int:
    issues: list[str] = []
    for key in ("run_id", "generated_at", "rollups", "findings", "sources"):
        if key not in data:
            issues.append(f"missing required key: {key!r}")
    roll = data.get("rollups") or {}
    if not isinstance(roll, dict):
        issues.append("'rollups' must be an object")
    else:
        if "total_findings" not in roll:
            issues.append("missing rollups.total_findings")
        fbs = roll.get("findings_by_severity") or {}
        if fbs and not isinstance(fbs, dict):
            issues.append("rollups.findings_by_severity must be an object")
        findings = data.get("findings")
        if isinstance(findings, list) and isinstance(fbs, dict):
            summed = sum(v for v in fbs.values() if isinstance(v, int))
            if summed != len(findings):
                issues.append(
                    f"findings count ({len(findings)}) != "
                    f"sum(rollups.findings_by_severity) ({summed})"
                )

    findings = data.get("findings")
    if findings is not None and not isinstance(findings, list):
        issues.append("'findings' must be an array")

    if issues:
        print("[!] Suite report verification failed:", file=sys.stderr)
        for line in issues:
            print(f"    - {line}", file=sys.stderr)
        return 1

    n = len(findings) if isinstance(findings, list) else 0
    print(f"[+] BitReport unified suite JSON OK: {path.name} ({n} normalized finding(s))")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Validate BitProbe scan JSON or BitReport unified suite JSON."""
    raw_path = Path(args.report_json)
    path = raw_path if raw_path.is_absolute() else _REPO_ROOT / raw_path
    if not path.is_file():
        print(f"[!] Not a file: {path}", file=sys.stderr)
        return 1

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[!] Cannot read file: {e}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("[!] Report root must be a JSON object.", file=sys.stderr)
        return 1

    if data.get("report_type") == "unified_suite" or data.get(
        "bitreport_schema_version"
    ):
        return _verify_suite_json(data, path)

    issues: list[str] = []

    required_keys = ("scan_id", "target", "findings", "statistics")
    for key in required_keys:
        if key not in data:
            issues.append(f"missing required key: {key!r}")

    findings = data.get("findings")
    if findings is not None and not isinstance(findings, list):
        issues.append("'findings' must be an array")

    stats = data.get("statistics")
    if stats is not None:
        if not isinstance(stats, dict):
            issues.append("'statistics' must be an object")
        else:
            fbs = stats.get("findings_by_severity")
            if fbs is not None:
                if not isinstance(fbs, dict):
                    issues.append("'statistics.findings_by_severity' must be an object")
                else:
                    for k, v in fbs.items():
                        if not _severity_bucket(k):
                            issues.append(
                                f"unexpected severity bucket in statistics: {k!r}"
                            )
                        if not isinstance(v, int) or v < 0:
                            issues.append(
                                f"invalid count for severity {k!r}: expected non-negative int"
                            )

    if isinstance(findings, list) and isinstance(stats, dict):
        fbs = stats.get("findings_by_severity")
        if isinstance(fbs, dict):
            summed = sum(v for v in fbs.values() if isinstance(v, int))
            n_findings = len(findings)
            if summed != n_findings:
                issues.append(
                    f"findings count ({n_findings}) != sum(findings_by_severity) ({summed})"
                )

    if findings:
        for i, item in enumerate(findings[:50]):
            if not isinstance(item, dict):
                issues.append(f"findings[{i}] must be an object")
                continue
            if "severity" in item and not _severity_bucket(item["severity"]):
                issues.append(f"findings[{i}].severity unknown value: {item['severity']!r}")

    if issues:
        print("[!] Verification failed:", file=sys.stderr)
        for line in issues:
            print(f"    - {line}", file=sys.stderr)
        return 1

    n = len(findings) if isinstance(findings, list) else 0
    print(f"[+] BitProbe report OK: {path.name} ({n} finding(s))")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bitai",
        description=(
            "BitAI — suite orchestration (roadmap) and report verification "
            f"(BitProbe / unified suite JSON; suite {SUITE_VERSION})."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Describe BitAI and subcommands")
    p_info.set_defaults(func=cmd_info)

    p_ver = sub.add_parser("version", help="Show scaffold version")
    p_ver.set_defaults(func=cmd_version)

    p_suite = sub.add_parser(
        "suite",
        help="List all BitSentry products (shared registry)",
    )
    p_suite.set_defaults(func=cmd_suite)

    p_verify = sub.add_parser(
        "verify",
        help="Validate BitProbe scan JSON or BitReport unified suite JSON",
    )
    p_verify.add_argument(
        "report_json",
        help="Path to report .json (BitProbe scan or bitsentry_suite_report)",
    )
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
