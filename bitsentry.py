#!/usr/bin/env python3
"""
BitSentry — multi-product security suite

Products (see `python bitsentry.py products`):
  BitProbe   — web vulnerability scanner
  BitScope   — attack surface / asset discovery
  BitWatch   — continuous monitoring (web, internal, cloud)
  BitGraph   — attack path analysis
  BitIntel   — vulnerability intelligence
  BitReport  — central reporting platform
  BitSpear   — internal network assessment / automated pentest agent
  BitCannon  — external technical attack simulation (no social engineering)
  BitAI      — orchestration, gap testing, third-party tools, report verification

Shortcuts:
    python bitsentry.py version
    python bitsentry.py products [--json]
    python bitsentry.py scan example.com
    python bitsentry.py scan example.com --suite-out ./suite_runs \\
        --suite-report --suite-verify
    python bitsentry.py discover example.com   # BitScope
    python bitsentry.py light-scan example.com # BitProbe only
    python bitsentry.py bitprobe scan example.com
    python bitsentry.py bitai verify report.json
    python bitsentry.py update-db
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from products import (
    SUITE_PRODUCTS,
    SUITE_VERSION,
    format_suite_overview,
    product_by_cli,
    script_path,
)
from suite_run import (
    append_history_run,
    new_run_id,
    slug_target,
    update_manifest,
    write_json,
    write_manifest,
)

BITSENTRY_DIR = Path(__file__).parent.resolve()
_BITSCOPE = product_by_cli("bitscope")
_BITPROBE = product_by_cli("bitprobe")
_BITAI = product_by_cli("bitai")
if _BITSCOPE is None or _BITPROBE is None:
    raise RuntimeError("products.SUITE_PRODUCTS must define bitscope and bitprobe")
BITSCOPE_PATH = script_path(_BITSCOPE)
BITPROBE_PATH = script_path(_BITPROBE)
BITAI_PATH = script_path(_BITAI) if _BITAI else None
BITREPORT_PATH = BITSENTRY_DIR / "bitreport" / "bitreport.py"


def _run_with_heartbeat(
    cmd: list[str],
    *,
    cwd: Path,
    label: str,
    quiet: bool,
    capture_stdout: bool,
    capture_stderr: bool,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a child process and print periodic status while it is still running."""
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE if capture_stdout else None,
        stderr=subprocess.PIPE if capture_stderr else None,
        text=True,
        env=env,
    )
    started = time.monotonic()
    next_tick = started + 5.0
    while proc.poll() is None:
        if not quiet and time.monotonic() >= next_tick:
            elapsed = int(time.monotonic() - started)
            print(f"[*] {label} still running... {elapsed}s elapsed", file=sys.stderr)
            next_tick += 5.0
        time.sleep(0.2)
    stdout_data, stderr_data = proc.communicate()
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode if proc.returncode is not None else 1,
        stdout=stdout_data,
        stderr=stderr_data,
    )


def _hostname_from_scan_target(raw: str) -> str:
    """Bare hostname from a URL or domain string (for www vs apex logic)."""
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    return (urlparse(value).hostname or "").strip().rstrip(".")


def _omit_redundant_www_when_user_chose_apex(primary: str, targets: list[str]) -> list[str]:
    """
    If the user targets the apex host (not www), omit www.<apex> from follow-on
    scans. Many sites only redirect www → apex; scanning www separately adds
    noise and can fail where the apex works.
    """
    ph = _hostname_from_scan_target(primary)
    if not ph or ph.startswith("www."):
        return targets
    www_only = f"www.{ph}"
    return [t for t in targets if _hostname_from_scan_target(t) != www_only]


def _parse_bitscope_discovery_json(raw: str) -> dict:
    """Parse BitScope JSON from stdout; tolerate surrounding whitespace."""
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        raise


def run_bitscope(
    domain: str,
    output_format: str = "json",
    verbose: bool = False,
    quiet: bool = False,
) -> dict:
    """Run BitScope discovery; returns parsed dict for JSON, or {} on failure."""
    cmd = [
        sys.executable,
        str(BITSCOPE_PATH),
        "discover",
        domain,
        "--output",
        output_format,
    ]
    if quiet:
        cmd.append("--quiet")
    elif not quiet:
        cmd.append("--verbose")

    result = _run_with_heartbeat(
        cmd,
        cwd=BITSCOPE_PATH.parent,
        label="BitScope discovery",
        quiet=quiet,
        capture_stdout=True,
        capture_stderr=quiet,
    )
    if quiet and result.stderr:
        sys.stderr.write(result.stderr)

    if result.returncode != 0:
        print(
            f"[!] BitScope failed (exit {result.returncode}).",
            file=sys.stderr,
        )
        return {}

    if output_format == "json":
        try:
            return _parse_bitscope_discovery_json(result.stdout)
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse BitScope JSON: {e}", file=sys.stderr)
            snippet = (result.stdout or "")[:500]
            print(f"[!] Raw output (truncated): {snippet!r}", file=sys.stderr)
            return {}
    return {}


def run_bitprobe(
    target: str,
    plugins: list | None = None,
    report_format: str | None = None,
    quiet: bool = False,
    output_name: str | None = None,
    output_dir: str | None = None,
    verbose: bool = False,
    skip_asn_refresh: bool = False,
) -> subprocess.CompletedProcess:
    """Run BitProbe scan. When quiet is False, stdout/stderr stream live to the terminal."""
    cmd = [sys.executable, str(BITPROBE_PATH), "scan", target]

    if verbose:
        cmd.append("-v")
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])
    if report_format:
        cmd.extend(["--format", report_format])
    if output_name:
        cmd.extend(["-o", output_name])
    if output_dir:
        cmd.extend(["--output-dir", output_dir])

    env = None
    if skip_asn_refresh:
        env = dict(os.environ)
        env["BITSENTRY_ASN_PRECHECKED"] = "1"

    if quiet:
        return _run_with_heartbeat(
            cmd,
            cwd=BITPROBE_PATH.parent,
            label=f"BitProbe scan ({target})",
            quiet=True,
            capture_stdout=True,
            capture_stderr=True,
            env=env,
        )

    return _run_with_heartbeat(
        cmd,
        cwd=BITPROBE_PATH.parent,
        label=f"BitProbe scan ({target})",
        quiet=False,
        capture_stdout=False,
        capture_stderr=False,
        env=env,
    )


def run_asn_precheck(verbose: bool = False, quiet: bool = False) -> int:
    """Run ASN DB check/update before suite scan."""
    cmd = [sys.executable, str(BITPROBE_PATH), "update-asn-db"]
    if verbose:
        cmd.append("-v")
    r = _run_with_heartbeat(
        cmd,
        cwd=BITPROBE_PATH.parent,
        label="ASN DB pre-check",
        quiet=quiet,
        capture_stdout=quiet,
        capture_stderr=quiet,
    )
    if quiet and r.stdout:
        sys.stdout.write(r.stdout)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _merge_report_formats(user_format: str | None, require_json: bool) -> str | None:
    parts: list[str] = []
    seen: set[str] = set()
    raw = (user_format or "").strip()
    if raw:
        for x in raw.split(","):
            x = x.strip().lower()
            if x and x not in seen:
                seen.add(x)
                parts.append(x)
    if require_json and "json" not in seen:
        parts.insert(0, "json")
        seen.add("json")
    return ",".join(parts) if parts else None


def _run_suite_bitreport(
    *,
    run_dir: Path,
    bitprobe_paths: list[Path],
    bitscope_path: Path | None,
    formats: str,
    try_npm: bool,
    quiet: bool,
) -> int:
    out = run_dir / "suite_report"
    cmd: list[str] = [
        sys.executable,
        str(BITREPORT_PATH),
        "build",
        "-o",
        str(out),
        "--name",
        "bitsentry_suite_report",
        "--formats",
        formats,
    ]
    inc: list[str] = []
    if bitprobe_paths:
        inc.append("bitprobe")
        for p in bitprobe_paths:
            cmd.extend(["--bitprobe", str(p.resolve())])
    if bitscope_path and bitscope_path.is_file():
        inc.append("bitscope")
        cmd.extend(["--bitscope", str(bitscope_path.resolve())])
    if not inc:
        print("[!] suite-report: no artifacts to aggregate.", file=sys.stderr)
        return 1
    cmd.extend(["--include", ",".join(inc)])
    if try_npm:
        cmd.append("--try-npm")
    kwargs: dict = {"cwd": str(BITSENTRY_DIR)}
    if quiet:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    r = subprocess.run(cmd, **kwargs)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _run_suite_verify(suite_json: Path, quiet: bool) -> int:
    if not BITAI_PATH:
        print("[!] BitAI path unknown; skip verify.", file=sys.stderr)
        return 0
    cmd = [sys.executable, str(BITAI_PATH), "verify", str(suite_json.resolve())]
    kwargs: dict = {"cwd": str(BITSENTRY_DIR)}
    if quiet:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    r = subprocess.run(cmd, **kwargs)
    if quiet and r.stdout:
        sys.stdout.write(r.stdout)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _copy_history_to_dashboard(suite_base: Path, dashboard_dir: Path) -> None:
    hist = suite_base / "history.json"
    if hist.is_file() and dashboard_dir.is_dir():
        shutil.copyfile(hist, dashboard_dir / "history.json")


def full_scan(target: str, args: argparse.Namespace) -> int:
    """
    Full security assessment:
    1. BitScope: Discover attack surface
    2. BitProbe: Scan discovered assets
    """
    quiet = getattr(args, "quiet", False)
    suite_base_opt = getattr(args, "suite_out", None)
    suite_base = Path(suite_base_opt).resolve() if suite_base_opt else None
    suite_report_flag = getattr(args, "suite_report", False)
    suite_verify_flag = getattr(args, "suite_verify", False)
    suite_try_npm = getattr(args, "suite_try_npm", False)
    suite_formats = getattr(args, "suite_report_formats", "json,pdf,dashboard")

    if suite_report_flag and not suite_base_opt:
        print("[!] --suite-report requires --suite-out DIR", file=sys.stderr)
        return 2
    if suite_verify_flag and not suite_report_flag:
        print("[!] --suite-verify requires --suite-report", file=sys.stderr)
        return 2

    run_dir: Path | None = None
    run_id: str | None = None
    manifest_path: Path | None = None
    bitscope_file: Path | None = None
    bitprobe_artifacts: list[Path] = []

    if suite_base:
        run_id = new_run_id()
        run_dir = suite_base / f"run_{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = run_dir / "manifest.json"
        write_manifest(
            manifest_path,
            {
                "run_id": run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "primary_target": target,
                "paths": {
                    "bitscope_discovery": "bitscope_discovery.json",
                    "bitprobe_reports": [],
                },
            },
        )

    if not quiet:
        print("=" * 60)
        print(f"BitSentry Full Security Scan: {target}")
        print("=" * 60)
        print()

    # Pre-flight: ASN database freshness/update (before BitScope)
    asn_rc = run_asn_precheck(
        verbose=bool(getattr(args, "verbose", False)),
        quiet=quiet,
    )
    asn_prechecked = asn_rc == 0
    if asn_rc != 0 and not quiet:
        print(
            "[!] ASN DB pre-check failed; continuing scan and allowing BitProbe fallback.",
            file=sys.stderr,
        )

    # Phase 1: Discovery
    if not quiet:
        print("[Phase 1] Attack Surface Discovery (BitScope)")
        print("-" * 60)

    verbose = bool(getattr(args, "verbose", False))

    discovery = run_bitscope(
        target,
        output_format="json",
        verbose=verbose,
        quiet=quiet,
    )

    if run_dir and manifest_path:
        if discovery:
            bitscope_file = run_dir / "bitscope_discovery.json"
            write_json(bitscope_file, discovery)
            bsd_name: str | None = "bitscope_discovery.json"
        else:
            bsd_name = None
        update_manifest(
            manifest_path,
            paths={"bitscope_discovery": bsd_name, "bitprobe_reports": []},
        )

    if not discovery:
        if not quiet:
            print("[!] Discovery failed, falling back to direct scan")
        targets_to_scan = [target]
    else:
        targets_to_scan = [target]

        subdomains = discovery.get("discovery", {}).get("subdomains", {})
        all_unique = subdomains.get("all_unique", [])

        max_subdomains = getattr(args, "max_subdomains", 10)
        for sub in all_unique[:max_subdomains]:
            if sub != target:
                targets_to_scan.append(sub)

        if not quiet:
            print(f"\n[+] Discovered {len(all_unique)} subdomains")
            print(
                f"[+] Will scan {len(targets_to_scan)} target(s) "
                f"(primary + up to {max_subdomains} from list)"
            )

    targets_to_scan = _omit_redundant_www_when_user_chose_apex(target, targets_to_scan)

    if not quiet:
        print()

    # Phase 2: Scanning
    if not quiet:
        print("[Phase 2] Vulnerability Scanning (BitProbe)")
        print("-" * 60)

    plugins = None
    if getattr(args, "plugins", None):
        plugins = [p.strip() for p in args.plugins.split(",") if p.strip()]

    user_format = getattr(args, "format", None) or None
    if user_format is not None:
        user_format = user_format.strip() or None
    report_format = _merge_report_formats(user_format, require_json=bool(run_dir))

    runs_root_str = str(run_dir.resolve()) if run_dir else None
    rel_names: list[str] = []

    failures = 0
    for i, scan_target in enumerate(targets_to_scan, 1):
        if not quiet:
            print(f"\n[{i}/{len(targets_to_scan)}] Scanning {scan_target}...")
        out_name = (
            f"bitprobe_{i:02d}_{slug_target(scan_target)}"
            if run_dir
            else None
        )
        proc = run_bitprobe(
            scan_target,
            plugins=plugins,
            report_format=report_format,
            quiet=quiet,
            output_name=out_name,
            output_dir=runs_root_str,
            verbose=verbose,
            skip_asn_refresh=asn_prechecked,
        )
        if proc.returncode != 0:
            failures += 1
            if quiet:
                print(
                    proc.stderr or proc.stdout or "(no output)",
                    file=sys.stderr,
                )
        elif run_dir and out_name:
            jp = run_dir / f"{out_name}.json"
            if jp.is_file():
                bitprobe_artifacts.append(jp)
                rel_names.append(f"{out_name}.json")
                if manifest_path:
                    update_manifest(
                        manifest_path,
                        paths={
                            "bitscope_discovery": "bitscope_discovery.json"
                            if bitscope_file and bitscope_file.is_file()
                            else None,
                            "bitprobe_reports": rel_names,
                        },
                    )

    if not quiet:
        print()
        print("=" * 60)
        print("Scan Complete")
        print("=" * 60)
        print(f"Targets scanned: {len(targets_to_scan)}")
        print()
        print("Discovered assets:")

    if discovery:
        subdomains = discovery.get("discovery", {}).get("subdomains", {})
        if not quiet:
            print(f"  - Subdomains: {len(subdomains.get('all_unique', []))}")

        cloud = discovery.get("discovery", {}).get("cloud_assets", {})
        cloud_count = sum(
            len(v) for v in cloud.values() if isinstance(v, list)
        )
        if not quiet:
            print(f"  - Cloud assets: {cloud_count}")
    elif not quiet:
        print("  - (discovery unavailable)")

    if quiet:
        print(
            f"[BitSentry] full-scan finished: {len(targets_to_scan)} target(s), "
            f"{failures} failure(s).",
            file=sys.stderr,
        )

    if failures:
        if not quiet:
            print(
                f"\n[!] {failures} scan(s) failed (see output above).",
                file=sys.stderr,
            )
        if not (suite_base and suite_report_flag):
            return 1

    exit_code = 1 if failures else 0

    if suite_base and run_dir and suite_report_flag:
        bs_path = bitscope_file if bitscope_file and bitscope_file.is_file() else None
        brc = _run_suite_bitreport(
            run_dir=run_dir,
            bitprobe_paths=bitprobe_artifacts,
            bitscope_path=bs_path,
            formats=suite_formats,
            try_npm=suite_try_npm,
            quiet=quiet,
        )
        if brc != 0:
            print("[!] BitReport suite build failed.", file=sys.stderr)
            exit_code = 1
        else:
            suite_json = run_dir / "suite_report" / "bitsentry_suite_report.json"
            if suite_json.is_file():
                try:
                    report_obj = json.loads(suite_json.read_text(encoding="utf-8"))
                    append_history_run(
                        suite_base,
                        run_id=report_obj.get("run_id", run_id or ""),
                        generated_at=report_obj.get("generated_at", ""),
                        primary_target=target,
                        report=report_obj,
                        run_dir_rel=run_dir.name,
                    )
                except (OSError, json.JSONDecodeError) as e:
                    print(f"[!] Could not update suite history: {e}", file=sys.stderr)
                dash = run_dir / "suite_report" / "dashboard"
                _copy_history_to_dashboard(suite_base, dash)
            else:
                print(
                    "[!] Expected suite JSON missing after BitReport; check PDF/dashboard errors.",
                    file=sys.stderr,
                )
                exit_code = 1
            if (
                suite_verify_flag
                and suite_json.is_file()
                and BITAI_PATH
            ):
                vrc = _run_suite_verify(suite_json, quiet=quiet)
                if vrc != 0:
                    print("[!] BitAI verify reported issues (see above).", file=sys.stderr)
                    exit_code = 1

            if manifest_path and suite_json.is_file():
                update_manifest(
                    manifest_path,
                    suite_report={
                        "output_dir": "suite_report",
                        "master_json": "suite_report/bitsentry_suite_report.json",
                        "dashboard_index": "suite_report/dashboard/index.html",
                    },
                )

    return exit_code


def main() -> int:
    quiet_help = (
        "Less noise: skip suite banners in full-scan; BitScope stderr suppressed; "
        "BitProbe output captured (full-scan/scan echoes it on failure only when quiet)."
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help=quiet_help,
    )
    common.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output: show every check, URL, and plugin execution.",
    )

    parser = argparse.ArgumentParser(
        description="BitSentry - Complete Security Assessment Suite",
        prog="bitsentry",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help=f"{quiet_help} Can also appear after subcommand.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output: show every check, URL, and plugin execution.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    products_parser = subparsers.add_parser(
        "products",
        help="List every suite product, status, and summary",
    )
    products_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the suite registry as JSON (for scripts and CI)",
    )

    subparsers.add_parser(
        "version",
        help="Print BitSentry suite version string",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Complete assessment (default): discovery + vulnerability scanning",
        parents=[common],
    )
    scan_parser.add_argument("target", help="Target domain")
    scan_parser.add_argument(
        "--max-subdomains",
        "-m",
        type=int,
        default=10,
        help="Maximum subdomains to scan (default: 10)",
    )
    scan_parser.add_argument(
        "--plugins",
        "-p",
        help="Comma-separated BitProbe plugins (passed through to bitprobe scan)",
    )
    scan_parser.add_argument(
        "--format",
        "-F",
        metavar="FMT",
        help=(
            "BitProbe report formats: json, md, pdf, html, all or comma-separated "
            "(default: bitprobe's default if omitted)"
        ),
    )
    scan_parser.add_argument(
        "--suite-out",
        metavar="DIR",
        help=(
            "Write this run under DIR/run_<id>/ (BitScope JSON, BitProbe artifacts, manifest.json)"
        ),
    )
    scan_parser.add_argument(
        "--suite-report",
        action="store_true",
        help=(
            "After scans, build BitReport (master JSON + PDF + dashboard) under run dir"
        ),
    )
    scan_parser.add_argument(
        "--suite-verify",
        action="store_true",
        help="Run BitAI verify on the suite JSON after --suite-report (BitReport must succeed)",
    )
    scan_parser.add_argument(
        "--suite-report-formats",
        default="json,pdf,dashboard",
        help="Forwarded to bitreport build --formats (default: json,pdf,dashboard)",
    )
    scan_parser.add_argument(
        "--suite-try-npm",
        action="store_true",
        help="Forward --try-npm to bitreport if dashboard dist is missing",
    )

    full_parser = subparsers.add_parser(
        "full-scan",
        help="Alias for scan (backwards compatible)",
        parents=[common],
    )
    full_parser.add_argument("target", help=argparse.SUPPRESS)
    full_parser.add_argument("--max-subdomains", "-m", type=int, default=10, help=argparse.SUPPRESS)
    full_parser.add_argument("--plugins", "-p", help=argparse.SUPPRESS)
    full_parser.add_argument("--format", "-F", metavar="FMT", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-out", metavar="DIR", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-report", action="store_true", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-verify", action="store_true", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-report-formats", default="json,pdf,dashboard", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-try-npm", action="store_true", help=argparse.SUPPRESS)

    discover_parser = subparsers.add_parser(
        "discover",
        help="Attack surface discovery only (BitScope)",
        parents=[common],
    )
    discover_parser.add_argument("target", help="Target domain")
    discover_parser.add_argument(
        "--output",
        "-o",
        choices=["json", "yaml", "table"],
        default="table",
    )

    probe_scan_parser = subparsers.add_parser(
        "light-scan",
        help="BitProbe-only vulnerability scan",
        parents=[common],
    )
    probe_scan_parser.add_argument("target", help="Target URL/domain")
    probe_scan_parser.add_argument(
        "--plugins",
        "-p",
        help="Comma-separated plugin list",
    )
    probe_scan_parser.add_argument(
        "--format",
        "-F",
        metavar="FMT",
        help=(
            "Report formats: json, md, pdf, html, all or comma-separated "
            "(default: bitprobe default if omitted)"
        ),
    )
    probe_scan_alias = subparsers.add_parser(
        "probe-scan",
        help="Alias for light-scan (backwards compatible)",
        parents=[common],
    )
    probe_scan_alias.add_argument("target", help=argparse.SUPPRESS)
    probe_scan_alias.add_argument("--plugins", "-p", help=argparse.SUPPRESS)
    probe_scan_alias.add_argument("--format", "-F", metavar="FMT", help=argparse.SUPPRESS)

    asn_db_parser = subparsers.add_parser(
        "update-asn-db",
        help=(
            "Refresh BitProbe ASN allocation DB (HEAD check; skips full download if unchanged)"
        ),
        parents=[common],
    )
    asn_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild the delegated file from RIPE",
    )
    update_db_parser = subparsers.add_parser(
        "update-db",
        help="Update BitProbe ASN database",
        parents=[common],
    )
    update_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild the delegated file from RIPE",
    )
    cve_db_parser = subparsers.add_parser(
        "update-cve-db",
        help="Update BitProbe CVE database from NVD",
        parents=[common],
    )
    cve_db_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days back to fetch CVEs (default: 30)",
    )
    subparsers.add_parser(
        "cve-stats",
        help="Show BitProbe CVE database statistics",
        parents=[common],
    )
    subparsers.add_parser(
        "profiles",
        help="List BitProbe scan profiles",
        parents=[common],
    )

    for spec in SUITE_PRODUCTS:
        subparsers.add_parser(
            spec.cli_name,
            help=f"{spec.display_name} [{spec.status}]",
        ).add_argument(
            "product_args",
            nargs=argparse.REMAINDER,
            help=argparse.SUPPRESS,
        )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    quiet = bool(getattr(args, "quiet", False))

    if args.command == "products":
        if getattr(args, "json", False):
            print(
                json.dumps(
                    [dataclasses.asdict(p) for p in SUITE_PRODUCTS],
                    indent=2,
                )
            )
        else:
            print(format_suite_overview())
        return 0

    if args.command == "version":
        print(f"BitSentry {SUITE_VERSION}")
        return 0

    if args.command in {"update-asn-db", "update-db"}:
        cmd = [sys.executable, str(BITPROBE_PATH), "update-asn-db"]
        if getattr(args, "verbose", False):
            cmd.append("-v")
        if getattr(args, "force", False):
            cmd.append("--force")
        return subprocess.run(cmd, cwd=str(BITPROBE_PATH.parent)).returncode
    if args.command == "update-cve-db":
        cmd = [sys.executable, str(BITPROBE_PATH), "update-cve-db"]
        if getattr(args, "days", None) is not None:
            cmd.extend(["--days", str(args.days)])
        return subprocess.run(cmd, cwd=str(BITPROBE_PATH.parent)).returncode
    if args.command == "cve-stats":
        cmd = [sys.executable, str(BITPROBE_PATH), "cve-stats"]
        return subprocess.run(cmd, cwd=str(BITPROBE_PATH.parent)).returncode
    if args.command == "profiles":
        cmd = [sys.executable, str(BITPROBE_PATH), "profiles"]
        return subprocess.run(cmd, cwd=str(BITPROBE_PATH.parent)).returncode

    delegate_names = {p.cli_name for p in SUITE_PRODUCTS}
    if args.command in delegate_names:
        spec = product_by_cli(args.command)
        assert spec is not None
        script = script_path(spec)
        child = [a for a in (getattr(args, "product_args", None) or []) if a]
        return subprocess.run(
            [sys.executable, str(script)] + child,
            cwd=str(script.parent),
        ).returncode

    if args.command in {"scan", "full-scan"}:
        return full_scan(args.target, args)

    if args.command == "discover":
        cmd = [
            sys.executable,
            str(BITSCOPE_PATH),
            "discover",
            args.target,
            "--output",
            args.output,
        ]
        if not quiet:
            cmd.append("--verbose")
        if quiet:
            cmd.append("--quiet")
        out = subprocess.PIPE if quiet else None
        err = subprocess.PIPE if quiet else None
        r = subprocess.run(
            cmd,
            cwd=str(BITSCOPE_PATH.parent),
            stdout=out,
            stderr=err,
            text=True,
        )
        if quiet and r.stdout:
            sys.stdout.write(r.stdout)
        if quiet and r.stderr:
            sys.stderr.write(r.stderr)
        return r.returncode

    if args.command in {"light-scan", "probe-scan"}:
        verbose = bool(getattr(args, "verbose", False))
        cmd = [sys.executable, str(BITPROBE_PATH), "scan", args.target]
        if verbose:
            cmd.append("-v")
        if args.plugins:
            cmd.extend(["--plugins", args.plugins])
        fmt = getattr(args, "format", None)
        if fmt and fmt.strip():
            cmd.extend(["--format", fmt.strip()])
        if quiet:
            r = subprocess.run(
                cmd,
                cwd=str(BITPROBE_PATH.parent),
                capture_output=True,
                text=True,
            )
            if r.stdout:
                sys.stdout.write(r.stdout)
            if r.stderr:
                sys.stderr.write(r.stderr)
            return r.returncode
        return subprocess.run(cmd, cwd=str(BITPROBE_PATH.parent)).returncode

    return 0


if __name__ == "__main__":
    sys.exit(main())
