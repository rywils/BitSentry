"""Golden JSON fixtures exercised through the real bitai verify CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BITAI = REPO / "bitai" / "bitai.py"
FIXTURES = REPO / "tests" / "fixtures"


def _run_verify(json_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BITAI), "verify", str(json_path)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )


def test_verify_unified_suite_ok() -> None:
    r = _run_verify(FIXTURES / "minimal_unified_suite_ok.json")
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout


def test_verify_unified_suite_detects_count_mismatch() -> None:
    r = _run_verify(FIXTURES / "minimal_unified_suite_bad_rollups.json")
    assert r.returncode == 1
    assert "findings count" in r.stderr


def test_verify_bitprobe_ok() -> None:
    r = _run_verify(FIXTURES / "minimal_bitprobe_ok.json")
    assert r.returncode == 0, r.stderr
    assert "BitProbe report OK" in r.stdout
