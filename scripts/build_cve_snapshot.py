#!/usr/bin/env python3
"""Build a validated, reproducible CVE database release artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_TABLES = frozenset({"cve_entries", "cve_products", "cve_cpes", "metadata"})
REQUIRED_METADATA = (
    "schema_version",
    "coverage_mode",
    "coverage_start",
    "coverage_end",
    "nvd_cursor",
)


def _inspect_database(path: Path) -> tuple[dict[str, str | None], int]:
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("CVE database failed integrity_check")
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not REQUIRED_TABLES <= tables:
            raise RuntimeError("CVE database is missing required tables")
        metadata = dict(conn.execute("SELECT key, value FROM metadata"))
        missing = [key for key in REQUIRED_METADATA if key not in metadata]
        if missing:
            raise RuntimeError(f"CVE database missing metadata: {missing}")
        if metadata["coverage_mode"] != "full":
            raise RuntimeError("refusing to publish a non-full CVE database")
        if not metadata["nvd_cursor"]:
            raise RuntimeError("refusing to publish without nvd_cursor")
        count = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    return {key: metadata[key] for key in REQUIRED_METADATA}, count


def build_snapshot(
    database: Path,
    output_dir: Path,
    *,
    source_commit: str,
) -> dict[str, object]:
    metadata, count = _inspect_database(database)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = output_dir / "cve_db.sqlite.gz"
    with database.open("rb") as source, artifact.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0) as output:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                output.write(block)

    compressed = artifact.read_bytes()
    manifest: dict[str, object] = {
        "format_version": 1,
        "schema_version": int(metadata["schema_version"] or 0),
        "coverage_mode": metadata["coverage_mode"],
        "coverage_start": metadata["coverage_start"],
        "coverage_end": metadata["coverage_end"],
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nvd_cursor": metadata["nvd_cursor"],
        "cve_count": count,
        "artifact": artifact.name,
        "sha256_gz": hashlib.sha256(compressed).hexdigest(),
        "compressed_size": len(compressed),
        "uncompressed_size": database.stat().st_size,
        "source_commit": source_commit,
    }
    manifest_path = output_dir / "manifest.json"
    with tempfile.NamedTemporaryFile(
        dir=output_dir, prefix=".manifest-", suffix=".json", mode="w", encoding="utf-8", delete=False
    ) as temp_file:
        json.dump(manifest, temp_file, indent=2, sort_keys=True)
        temp_file.write("\n")
        temp_path = Path(temp_file.name)
    os.replace(temp_path, manifest_path)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    default_data = Path(os.environ.get("BITSENTRY_DATA_DIR", Path.home() / ".bitsentry" / "data"))
    parser.add_argument("--database", type=Path, default=default_data / "cve_db.sqlite")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    build_snapshot(
        args.database,
        args.output_dir,
        source_commit=os.environ.get("GITHUB_SHA", "unknown"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
