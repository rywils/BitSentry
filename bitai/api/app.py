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
    POST /api/bitai/chat  -> forwards to a skevor product's /api/chat route

skevor (~/github/skevor) resolves the tenant itself via getTenant() reading
skevor.config.json server-side, so this client sends only {input,
conversationId} and doesn't need to load or forward tenant config.

Note: skevor has no equivalent yet to the old toolEndpoints mapping that let
the agent invoke scan_target/fetch_cve/verify_vulnerability/
rule_out_false_positive/generate_report -- that needs a real skevor connector
(src/core/connectors/) in the skevor repo. This wires the chat proxy only.
"""
from __future__ import annotations

import os

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

SKEVOR_CHAT_URL = os.environ.get("SKEVOR_CHAT_URL", "http://localhost:3000/api/chat")


def _json_body() -> dict:
    """Parse the request JSON body, treating any non-dict payload as empty."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


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
    conversation_id = data.get("conversationId")

    # skevor's create-skevor-app web-chat template's POST /api/chat contract:
    # request {input, conversationId?} -> response {result, conversationId}.
    chat_request: dict = {"input": prompt}
    if conversation_id:
        chat_request["conversationId"] = conversation_id

    try:
        response = requests.post(SKEVOR_CHAT_URL, json=chat_request, timeout=10)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as exc:  # noqa: BLE001
        return (
            jsonify(
                {
                    "error": "skevor chat endpoint not reachable; returning intended input shape.",
                    "details": str(exc),
                    "skevor_chat_request": chat_request,
                }
            ),
            503,
        )


if __name__ == "__main__":
    # debug=True enables the Werkzeug interactive debugger, which allows
    # arbitrary code execution from anyone who can trigger an unhandled
    # exception and reach it over the network. Opt in explicitly for local
    # dev only, and never allow it while bound to every interface -- use
    # FLASK_HOST=127.0.0.1 for a debug session.
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    debug_requested = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes"}
    debug = debug_requested and host not in {"0.0.0.0", "::"}
    if debug_requested and not debug:
        print(f"[!] FLASK_DEBUG requested but host is {host!r}; refusing to enable the debugger on a non-loopback bind.")
    app.run(host=host, port=int(os.environ.get("PORT", "5000")), debug=debug)
