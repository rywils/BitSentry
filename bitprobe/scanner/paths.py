"""Resolved paths for BitProbe resources (cwd-independent)."""

from __future__ import annotations

from pathlib import Path

# bitprobe/ directory (parent of scanner/)
BITPROBE_ROOT: Path = Path(__file__).resolve().parents[1]

# Delegated-ASN JSON built by asn_db_updater
ASN_DB_PATH: str = str(BITPROBE_ROOT / "data" / "asn_db.json")
