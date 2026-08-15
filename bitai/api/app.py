#!/usr/bin/env python3
"""
BitAI API route stubs.

BitSentry is a Python project, so this is the Python/Flask equivalent of
Next.js `src/app/api/...` route files. Install Flask before running:
    pip install flask

Endpoints:
    POST /api/bitai/scan
    GET  /api/bitai/cve
    POST /api/bitai/verify
    POST /api/bitai/report
    POST /api/bitai/chat  -> attempts to call Proteus runAgent
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "proteus.config.json"
PROTEUS_RUN_URL = os.environ.get("PROTEUS_RUN_URL", "http://localhost:3000/api/agent/run")


def _json_body() -> dict:
    """Parse the request JSON body, treating any non-dict payload as empty."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _load_tenant() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _agent_config(tenant: dict) -> dict:
    default = tenant.get("defaultAgent")
    for agent in tenant.get("agents", []):
        if agent.get("id") == default:
            return agent
    return tenant.get("agents", [{}])[0]


@app.route("/api/bitai/scan", methods=["POST"])
def scan_target():
    body = _json_body()
    return jsonify(
        {
            "tool": "scan_target",
            "status": "mock",
            "target": body.get("target"),
            "findings": [],
            "message": "Wiring OK: scan target received.",
        }
    )


@app.route("/api/bitai/cve", methods=["GET"])
def fetch_cve():
    cve_id = request.args.get("cve_id", "CVE-0000-00000")
    return jsonify(
        {
            "tool": "fetch_cve",
            "status": "mock",
            "cve_id": cve_id,
            "summary": "Mock CVE entry.",
        }
    )


@app.route("/api/bitai/verify", methods=["POST"])
def verify_vulnerability():
    body = _json_body()
    tool_name = body.get("name", "verify_vulnerability")
    return jsonify(
        {
            "tool": tool_name,
            "status": "mock",
            "vulnerability": body.get("vulnerability"),
            "false_positive": body.get("false_positive", False),
            "message": "Wiring OK: verification received.",
        }
    )


@app.route("/api/bitai/report", methods=["POST"])
def generate_report():
    body = _json_body()
    return jsonify(
        {
            "tool": "generate_report",
            "status": "mock",
            "format": body.get("format", "json"),
            "report_url": "/mock/bitai_report.json",
        }
    )


@app.route("/api/bitai/chat", methods=["POST"])
def chat():
    data = _json_body()
    prompt = data.get("prompt", "")
    if not prompt:
        return jsonify({"error": "Missing 'prompt' in request body."}), 400

    try:
        tenant = _load_tenant()
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({"error": f"Could not load {CONFIG_PATH.name}: {exc}"}), 500

    agent_config = _agent_config(tenant)

    # Proteus runAgent input shape (see stock-ai/src/app/api/agent/run/route.ts)
    run_input = {
        "tenant": tenant,
        "agentConfig": agent_config,
        "input": prompt,
    }

    try:
        response = requests.post(
            PROTEUS_RUN_URL,
            json={"prompt": prompt},
            headers={"X-Tenant-Id": tenant.get("id", "")},
            timeout=10,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as exc:  # noqa: BLE001
        return (
            jsonify(
                {
                    "error": "Proteus runAgent endpoint not reachable; returning intended input shape.",
                    "details": str(exc),
                    "proteus_run_input": run_input,
                }
            ),
            503,
        )


if __name__ == "__main__":
    # debug=True enables the Werkzeug interactive debugger, which allows
    # arbitrary code execution from anyone who can trigger an unhandled
    # exception and reach it over the network. Opt in explicitly for local
    # dev only; never default it on for a process bound to 0.0.0.0.
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)
