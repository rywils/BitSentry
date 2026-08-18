"""Resolved paths for BitProbe resources (cwd-independent)."""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

# bitprobe/ directory (parent of scanner/)
BITPROBE_ROOT: Path = Path(__file__).resolve().parents[1]

BITSENTRY_STATE_DIR: Path = Path.home() / ".bitsentry"
BITSENTRY_DATA_DIR: Path = Path(
    os.environ.get("BITSENTRY_DATA_DIR", BITSENTRY_STATE_DIR / "data")
).expanduser()

LEGACY_CVE_DB_PATH: Path = BITPROBE_ROOT / "data" / "cve_db.sqlite"
CVE_DB_PATH: str = str(BITSENTRY_DATA_DIR / "cve_db.sqlite")
CVE_META_PATH: str = str(BITSENTRY_DATA_DIR / "cve_meta.json")

# Delegated-ASN JSON built by asn_db_updater
ASN_DB_PATH: str = str(BITPROBE_ROOT / "data" / "asn_db.json")

_CVE_REQUIRED_TABLES = frozenset(
    {"cve_entries", "cve_products", "cve_cpes", "metadata"}
)


def _valid_cve_database(path: Path) -> bool:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                return False
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            return _CVE_REQUIRED_TABLES <= tables
    except (OSError, sqlite3.Error):
        return False


def migrate_legacy_cve_database(
    legacy_path: Path = LEGACY_CVE_DB_PATH,
    destination: Path | None = None,
) -> bool:
    """Copy a valid legacy CVE DB once, leaving its source untouched."""
    destination = destination or Path(CVE_DB_PATH)
    if destination.exists() or not legacy_path.is_file():
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=".cve-migrate-",
            suffix=".sqlite",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
        shutil.copy2(legacy_path, temp_path)
        if not _valid_cve_database(temp_path):
            return False
        os.replace(temp_path, destination)
        temp_path = None
        return True
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
