"""Load BitProbe / BitScope artifacts and build a unified suite report dict."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: root must be an object")
    return data


def ingest_bitprobe_paths(paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        out.append(_load_json(p))
    return out


def ingest_bitscope(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return _load_json(path)


def _normalize_bitprobe_finding(
    scan_id: str,
    idx: int,
    finding: dict[str, Any],
    source_label: str,
) -> dict[str, Any]:
    sev = str(finding.get("severity", "info")).lower()
    return {
        "id": f"bitprobe:{scan_id}:{idx}",
        "source_product": "bitprobe",
        "source_artifact": source_label,
        "source_scan_id": scan_id,
        "severity": sev,
        "title": finding.get("title", ""),
        "url": finding.get("url", ""),
        "plugin_name": finding.get("plugin_name", ""),
        "description": finding.get("description", "")[:2000],
        "risk_score": finding.get("risk_score"),
    }


def build_unified_report(
    *,
    bitreport_schema_version: str,
    run_id: str,
    title: str,
    bitprobe_reports: list[tuple[str, dict[str, Any]]],
    bitscope_report: dict[str, Any] | None,
    include_bitprobe: bool,
    include_bitscope: bool,
) -> dict[str, Any]:
    """
    bitprobe_reports: list of (label, payload) e.g. file stem + loaded json
    """
    findings: list[dict[str, Any]] = []
    findings_by_severity: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    findings_by_plugin: dict[str, int] = {}

    sources: dict[str, Any] = {
        "bitprobe": {"included": include_bitprobe, "scans": []},
        "bitscope": {"included": bool(include_bitscope and bitscope_report), "summary": None},
    }

    if include_bitprobe:
        for label, rep in bitprobe_reports:
            scan_id = str(rep.get("scan_id", "unknown"))
            targets = rep.get("target", "")
            stats = rep.get("statistics") or {}
            sources["bitprobe"]["scans"].append(
                {
                    "artifact": label,
                    "scan_id": scan_id,
                    "target": targets,
                    "statistics": stats,
                    "finding_count": len(rep.get("findings") or []),
                }
            )
            for i, f in enumerate(rep.get("findings") or []):
                if not isinstance(f, dict):
                    continue
                nf = _normalize_bitprobe_finding(scan_id, i, f, label)
                findings.append(nf)
                sev = nf["severity"]
                if sev in findings_by_severity:
                    findings_by_severity[sev] += 1
                else:
                    findings_by_severity["info"] += 1
                plug = nf["plugin_name"] or "unknown"
                findings_by_plugin[plug] = findings_by_plugin.get(plug, 0) + 1

    if include_bitscope and bitscope_report:
        disc = bitscope_report.get("discovery") or {}
        sub = disc.get("subdomains") or {}
        cloud = disc.get("cloud_assets") or {}
        sources["bitscope"]["summary"] = {
            "domain": bitscope_report.get("domain"),
            "subdomain_count": len(sub.get("all_unique") or []),
            "cloud_bucket_counts": {
                k: len(v) for k, v in cloud.items() if isinstance(v, list)
            },
        }

    return {
        "bitreport_schema_version": bitreport_schema_version,
        "suite": "BitSentry",
        "report_type": "unified_suite",
        "title": title,
        "run_id": run_id,
        "generated_at": _utc_now_iso(),
        "sources": sources,
        "rollups": {
            "total_findings": len(findings),
            "findings_by_severity": findings_by_severity,
            "findings_by_plugin": dict(
                sorted(findings_by_plugin.items(), key=lambda kv: -kv[1])
            ),
        },
        "findings": findings,
        "raw_embed": {
            "bitprobe": [r for _, r in bitprobe_reports] if include_bitprobe else [],
            "bitscope": bitscope_report if include_bitscope else None,
        },
    }


def aggregate_from_cli_inputs(
    *,
    bitprobe_paths: list[Path],
    bitscope_path: Path | None,
    include: frozenset[str],
    report_title: str,
    schema_version: str,
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    include_bp = "bitprobe" in include and bool(bitprobe_paths)
    include_bs = "bitscope" in include and bitscope_path is not None

    bp_payloads: list[tuple[str, dict[str, Any]]] = []
    if bitprobe_paths:
        for p in bitprobe_paths:
            bp_payloads.append((p.stem, _load_json(p)))

    bs_payload = ingest_bitscope(bitscope_path) if bitscope_path else None

    return build_unified_report(
        bitreport_schema_version=schema_version,
        run_id=run_id,
        title=report_title,
        bitprobe_reports=bp_payloads,
        bitscope_report=bs_payload,
        include_bitprobe=include_bp,
        include_bitscope=bool(include_bs and bs_payload),
    )
