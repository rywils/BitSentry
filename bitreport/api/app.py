"""Local BitSentry web application API."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = Path(os.environ.get("BITSENTRY_RUNS_DIR", ROOT / "runs")).resolve()
DASHBOARD_DIR = ROOT / "bitreport" / "dashboard" / "dist"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="BitSentry", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    max_subdomains: int = Field(default=10, ge=0, le=100)


def _validate_target(target: str) -> str:
    value = target.strip()
    raw_scheme = urlparse(value).scheme.lower()
    if raw_scheme in {"data", "file", "ftp", "javascript", "ws", "wss"}:
        raise HTTPException(status_code=422, detail="Target must be an HTTP or HTTPS URL")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or any(char.isspace() for char in value)
    ):
        raise HTTPException(status_code=422, detail="Target must be an HTTP or HTTPS URL")
    return value


def _write_event(job_dir: Path, event: dict) -> None:
    with (job_dir / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")


def _latest_report(job_dir: Path) -> Path | None:
    reports = sorted(job_dir.glob("run_*/suite_report/bitsentry_suite_report.json"))
    return reports[-1] if reports else None


def _run_scan(job_id: str, target: str, max_subdomains: int) -> None:
    job_dir = RUNS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(ROOT / "bitsentry.py"),
        "scan",
        target,
        "--max-subdomains",
        str(max_subdomains),
        "--suite-out",
        str(job_dir),
        "--suite-report",
        "--suite-report-formats",
        "json",
        "--quiet",
    ]
    _write_event(job_dir, {"type": "started", "command": command[1:]})
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            message = line.rstrip()
            if message:
                _write_event(job_dir, {"type": "log", "message": message})
        return_code = process.wait()
        report_path = _latest_report(job_dir)
        status = "completed" if return_code == 0 and report_path else "failed"
        event = {"type": "finished", "status": status, "return_code": return_code}
        if report_path:
            event["report_id"] = report_path.parent.parent.name
        _write_event(job_dir, event)
        with _jobs_lock:
            _jobs[job_id].update({"status": status, "return_code": return_code, "report_path": str(report_path) if report_path else None})
    except OSError as exc:
        _write_event(job_dir, {"type": "finished", "status": "failed", "error": str(exc)})
        with _jobs_lock:
            _jobs[job_id].update({"status": "failed", "error": str(exc)})


def _job_summary(job_id: str, job: dict) -> dict:
    return {"id": job_id, **{key: value for key, value in job.items() if key != "report_path"}, "has_report": bool(job.get("report_path"))}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "bitsentry"}


@app.get("/api/scans")
def scans() -> list[dict]:
    with _jobs_lock:
        return [_job_summary(job_id, job) for job_id, job in _jobs.items()]


@app.post("/api/scans", status_code=202)
def start_scan(request: ScanRequest) -> dict:
    target = _validate_target(request.target)
    job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex()
    job = {"target": target, "status": "queued", "created_at": datetime.now(timezone.utc).isoformat()}
    with _jobs_lock:
        _jobs[job_id] = job
    threading.Thread(target=_run_scan, args=(job_id, target, request.max_subdomains), daemon=True).start()
    return _job_summary(job_id, job)


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _job_summary(job_id, job)


@app.get("/api/scans/{job_id}/events")
def scan_events(job_id: str) -> list[dict]:
    path = RUNS_DIR / job_id / "events.jsonl"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Scan not found")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _reports() -> list[tuple[str, Path]]:
    return [(path.parent.parent.parent.name, path) for path in RUNS_DIR.glob("*/run_*/suite_report/bitsentry_suite_report.json")]


@app.get("/api/runs")
def runs() -> list[dict]:
    result = []
    for report_id, path in _reports():
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        result.append({
            "id": report_id,
            "run_id": report.get("run_id"),
            "target": report.get("target") or report.get("title"),
            "generated_at": report.get("generated_at"),
            "total_findings": (report.get("rollups") or {}).get("total_findings", 0),
            "risk_level": ((report.get("rollups") or {}).get("risk") or {}).get("level"),
        })
    return sorted(result, key=lambda item: item.get("generated_at") or "", reverse=True)


@app.get("/api/runs/latest")
def latest_report() -> dict:
    available = runs()
    if not available:
        raise HTTPException(status_code=404, detail="No reports available")
    return run_report(available[0]["id"])


@app.get("/api/runs/{report_id}")
def run_report(report_id: str) -> dict:
    matches = [path for found_id, path in _reports() if found_id == report_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return json.loads(matches[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Report could not be read") from exc


if DASHBOARD_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=DASHBOARD_DIR / "assets"), name="assets")


@app.get("/{path:path}")
def frontend(path: str = ""):
    if not DASHBOARD_DIR.is_dir():
        return {"message": "Build the dashboard with npm run build", "api": "/api/health"}
    requested = (DASHBOARD_DIR / path).resolve()
    if requested.parent == DASHBOARD_DIR.resolve() and requested.is_file():
        return FileResponse(requested)
    return FileResponse(DASHBOARD_DIR / "index.html")
