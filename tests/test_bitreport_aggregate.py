"""BitReport aggregation logic (bitreport/ uses flat imports; path shim for tests)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BITREPORT = REPO / "bitreport"


@pytest.fixture(autouse=True)
def _bitreport_path() -> None:
    s = str(BITREPORT)
    if s not in sys.path:
        sys.path.insert(0, s)
    yield
    try:
        sys.path.remove(s)
    except ValueError:
        pass


def test_build_unified_report_bitprobe_only() -> None:
    from aggregate import build_unified_report

    bp = (
        "scan_a",
        {
            "scan_id": "s1",
            "target": "https://a.example",
            "findings": [
                {
                    "severity": "high",
                    "title": "X",
                    "url": "",
                    "plugin_name": "p",
                    "description": "",
                }
            ],
            "statistics": {},
        },
    )
    r = build_unified_report(
        bitreport_schema_version="1.0",
        run_id="r-test",
        title="T",
        bitprobe_reports=[bp],
        bitscope_report=None,
        include_bitprobe=True,
        include_bitscope=False,
    )
    assert r["report_type"] == "unified_suite"
    assert len(r["findings"]) == 1
    assert r["rollups"]["total_findings"] == 1
    assert r["rollups"]["findings_by_severity"]["high"] == 1
    summed = sum(
        v
        for v in r["rollups"]["findings_by_severity"].values()
        if isinstance(v, int)
    )
    assert summed == len(r["findings"])


def test_build_unified_report_empty_excluded() -> None:
    from aggregate import build_unified_report

    r = build_unified_report(
        bitreport_schema_version="1.0",
        run_id="r-empty",
        title="T",
        bitprobe_reports=[],
        bitscope_report=None,
        include_bitprobe=False,
        include_bitscope=False,
    )
    assert r["findings"] == []
    assert r["rollups"]["total_findings"] == 0
