#!/usr/bin/env python3
"""
BitProbe - Modular Security Vulnerability Scanner

Usage:
    bitprobe scan <target> [options]
    bitprobe update-asn-db
    bitprobe update-cve-db
    bitprobe profiles
"""

import argparse
import sys

from scanner.engine import ScanEngine
from scanner.config import ScanConfig, SCAN_PROFILES
from scanner.asn_db_updater import update_asn_db
from scanner.cve_db_manager import update_cve_database, get_stats


def cmd_scan(args) -> int:
    """Execute scan command."""
    formats = []
    if args.format:
        raw = args.format.strip().lower()
        if raw == "all":
            formats = ["json", "md", "pdf"]
        else:
            formats = [f.strip() for f in raw.split(",") if f.strip()]

    allowed = {"json", "md", "pdf", "html"}
    invalid = [fmt for fmt in formats if fmt not in allowed]
    if invalid:
        print(f"[!] Unsupported format(s): {', '.join(invalid)}", file=sys.stderr)
        return 1

    config_kwargs = {
        "target_url": args.target,
        "output_name": args.output,
        "output_formats": formats or ["json", "md", "pdf"],
        "profile": args.profile,
        "verbose": getattr(args, "verbose", False),
    }
    
    if args.depth is not None:
        config_kwargs["depth"] = args.depth
    if args.max_urls is not None:
        config_kwargs["max_urls"] = args.max_urls
    if args.rate_limit is not None:
        config_kwargs["rate_limit"] = args.rate_limit
    if args.workers is not None:
        config_kwargs["parallel_workers"] = args.workers
    if getattr(args, "plugins", None):
        config_kwargs["enabled_plugins"] = [
            p.strip() for p in args.plugins.split(",") if p.strip()
        ]
    if getattr(args, "output_dir", None):
        config_kwargs["output_dir"] = str(args.output_dir).strip()

    config = ScanConfig(**config_kwargs)
    engine = ScanEngine(config)

    try:
        report = engine.run_scan()
        return 0
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[!] Scan failed: {e}", file=sys.stderr)
        return 1


def cmd_profiles(args) -> int:
    """List available scan profiles."""
    print("\nAvailable Scan Profiles:")
    print("=" * 60)
    
    for name, profile in SCAN_PROFILES.items():
        print(f"\n{name}")
        print(f"  Description: {profile['description']}")
        print(f"  Depth: {profile['depth']}")
        print(f"  Max URLs: {profile['max_urls']}")
        print(f"  Rate Limit: {profile['rate_limit']}s")
        print(f"  Workers: {profile['parallel_workers']}")
        print(f"  Plugins: {', '.join(profile['enabled_plugins'])}")
    
    print("\nUsage: bitprobe scan <target> --profile <name>")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bitprobe",
        description="BitProbe - Modular Security Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    bitprobe scan example.com
    bitprobe scan example.com --profile quick
    bitprobe scan example.com --depth 3 --format json,md
    bitprobe update-asn-db
    bitprobe profiles
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "target",
        help="Target domain, IP address, or URL to scan",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Base output name for report files",
    )
    scan_parser.add_argument(
        "--output-dir",
        dest="output_dir",
        metavar="DIR",
        help="Directory for artifacts (default: REPORTS under repository root)",
    )
    scan_parser.add_argument(
        "--format",
        default="json,md,pdf,html",
        help="Comma-separated formats: json,md,pdf,html (default: all)",
    )
    scan_parser.add_argument(
        "--profile",
        choices=list(SCAN_PROFILES.keys()),
        help="Use a predefined scan profile",
    )
    scan_parser.add_argument(
        "--depth",
        type=int,
        help="Crawl depth (overrides profile)",
    )
    scan_parser.add_argument(
        "--max-urls",
        type=int,
        help="Maximum URLs to crawl (overrides profile)",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=float,
        help="Request rate limit in seconds (overrides profile)",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        help="Parallel worker threads (overrides profile)",
    )
    scan_parser.add_argument(
        "--plugins",
        "-p",
        help=(
            "Comma-separated plugins to run (overrides profile list). "
            "e.g. fingerprinting,security_headers,tls_analysis"
        ),
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output - show every URL, plugin execution, and check",
    )

    asn_db_parser = subparsers.add_parser(
        "update-asn-db",
        help=(
            "Update ASN database (public IP allocations). "
            "Skips full download when the RIPE delegated file is unchanged."
        ),
    )
    asn_db_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose progress",
    )
    asn_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild (ignore unchanged-source short-circuit)",
    )

    cve_parser = subparsers.add_parser(
        "update-cve-db",
        help="Update CVE database from NVD",
    )
    cve_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days back to fetch CVEs (default: 30)",
    )

    cve_stats_parser = subparsers.add_parser(
        "cve-stats",
        help="Show CVE database statistics",
    )

    subparsers.add_parser(
        "profiles",
        help="List available scan profiles",
    )

    args = parser.parse_args()

    verbose = getattr(args, "verbose", False)

    if args.command == "update-asn-db":
        update_asn_db(verbose=args.verbose, force=getattr(args, "force", False))
        return 0

    elif args.command == "update-cve-db":
        try:
            count = update_cve_database(days=args.days, verbose=verbose)
            print(f"[+] CVE database updated with {count} entries")
            return 0
        except Exception as e:
            print(f"[!] CVE update failed: {e}", file=sys.stderr)
            return 1

    elif args.command == "cve-stats":
        try:
            stats = get_stats()
            print("\nCVE Database Statistics")
            print("=" * 40)
            print(f"Total CVEs: {stats.get('total_cves', 0)}")
            print(f"Total Products: {stats.get('total_products', 0)}")
            print(f"Last Updated: {stats.get('last_updated', 'Never')}")
            print("\nBy Severity:")
            for sev, count in stats.get('severity_counts', {}).items():
                print(f"  {sev.upper()}: {count}")
            return 0
        except Exception as e:
            print(f"[!] Failed to get stats: {e}", file=sys.stderr)
            return 1

    elif args.command == "profiles":
        return cmd_profiles(args)

    elif args.command == "scan":
        return cmd_scan(args)
    
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
