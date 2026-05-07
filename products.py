"""
BitSentry suite registry — one place for product names, entrypoints, and blurbs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Monorepo / CLI version (orchestrator + registry). Bump when releasing.
SUITE_VERSION = "0.1.0"


@dataclass(frozen=True)
class SuiteProduct:
    """Describes one deliverable in the BitSentry suite."""

    cli_name: str
    script_relpath: str
    display_name: str
    summary: str
    status: str  # "implemented" | "scaffold"


REPO_ROOT = Path(__file__).resolve().parent

SUITE_PRODUCTS: tuple[SuiteProduct, ...] = (
    SuiteProduct(
        "bitprobe",
        "bitprobe/bitprobe.py",
        "BitProbe",
        "Web application vulnerability scanner and crawl-based security testing.",
        "implemented",
    ),
    SuiteProduct(
        "bitscope",
        "bitscope/bitscope.py",
        "BitScope",
        "External attack surface and asset discovery (DNS, CT, cloud hints, IP intel).",
        "implemented",
    ),
    SuiteProduct(
        "bitwatch",
        "bitwatch/bitwatch.py",
        "BitWatch",
        "Continuous monitoring across web, internal network, and cloud environments.",
        "scaffold",
    ),
    SuiteProduct(
        "bitgraph",
        "bitgraph/bitgraph.py",
        "BitGraph",
        "Attack path analysis — graph relationships between assets, exposures, and blast radius.",
        "scaffold",
    ),
    SuiteProduct(
        "bitintel",
        "bitintel/bitintel.py",
        "BitIntel",
        "Vulnerability intelligence: advisories, exploitability context, and enrichment pipelines.",
        "scaffold",
    ),
    SuiteProduct(
        "bitreport",
        "bitreport/bitreport.py",
        "BitReport",
        "Unified suite reporting: master JSON + PDF + React dashboard (BitProbe & BitScope MVP).",
        "implemented",
    ),
    SuiteProduct(
        "bitspear",
        "bitspear/bitspear.py",
        "BitSpear",
        "Internal network/host assessment and automated penetration agent "
        "(post-infiltration style, telemetry back to BitSentry).",
        "scaffold",
    ),
    SuiteProduct(
        "bitcannon",
        "bitcannon/bitcannon.py",
        "BitCannon",
        "External attacker simulation from outside the LAN — technical exploitation only "
        "(no social engineering).",
        "scaffold",
    ),
    SuiteProduct(
        "bitai",
        "bitai/bitai.py",
        "BitAI",
        "Report verification (BitProbe / unified suite JSON) plus suite overview; "
        "broader orchestration hooks remain roadmap.",
        "implemented",
    ),
)


def script_path(product: SuiteProduct) -> Path:
    return REPO_ROOT / product.script_relpath


def product_by_cli(name: str) -> SuiteProduct | None:
    n = name.lower().strip()
    for p in SUITE_PRODUCTS:
        if p.cli_name == n:
            return p
    return None


def format_suite_overview() -> str:
    lines = [
        "BitSentry — product suite",
        "=" * 64,
        "",
    ]
    for p in SUITE_PRODUCTS:
        lines.append(f"  {p.display_name}  ({p.cli_name})  [{p.status}]")
        lines.append(f"    {p.summary}")
        lines.append("")
    lines.append("Entry:  python bitsentry.py <product> ...")
    lines.append("        python bitsentry.py products")
    lines.append("")
    lines.append(
        "Tip: Product-native --help (e.g. bitprobe subcommands): "
        "python bitprobe/bitprobe.py --help"
    )
    return "\n".join(lines)
