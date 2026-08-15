# BitSentry

CLI-first security assessment suite. Public build covers external attack-surface discovery (`bitscope`) and web vulnerability scanning (`bitprobe`), orchestrated by `bitsentry.py`. A private edition with a web UI exists but isn't in this repo.

> Only ever scan targets you own or are explicitly authorized to test.

## Stack

- **Python 3.12+** — everything except the network scan engine. No framework; plain `argparse` CLIs per module.
- **Rust** — `bitprobe/engines/rust/bitprobe_engine` (edition 2021, tokio/rusqlite/reqwest/clap). Compiled binary at `target/release/bitprobe-engine`, invoked via `subprocess` from `bitprobe/scanner/engines/network/__init__.py`.
- **TypeScript/Vite** — `bitreport/dashboard`, a small report-viewing frontend. Separate from the CLI.
- **Docker** — `Dockerfile` + `docker-compose.yml` for running the suite in a container.

## Architecture

Each `bitX/` directory at the repo root is a semi-independent product with its own `bitX.py` entrypoint. `bitsentry.py` is the unified dispatcher (`scan`, `discover`, `light-scan`, `products`, plus per-product subcommands).

`bitprobe` is the most developed module and uses a plugin architecture:
- `bitprobe/plugins/base_plugin.py` defines `Finding` (severity, evidence, remediation, computed risk_score) — the common output type every plugin returns.
- `bitprobe/scanner/plugin_resolver.py` loads enabled plugins (waf_detection, tls_analysis, security_headers, cve_correlation, sensitive_files, asn_intel, infrastructure_intel, api_discovery, ip_intel).
- `bitprobe/scanner/engine.py` drives crawl (`crawler.py`/`smart_crawler.py`) → plugin scan → output formatting (json/md/pdf).

CVE correlation (`bitprobe/plugins/cve_correlation.py`) does CPE parsing + semver range matching + product aliasing against a local CVE store, not naive string matching — this was a deliberate fix for false-positive CVEs (see git history).

Network scanning has a fallback chain in `bitprobe/scanner/engines/network/__init__.py`: Rust binary first, then Go (built on demand if `go` is on PATH), then pure Python. **Note:** the Rust engine's own README says "Rust is the ONLY scanning engine" — that contradicts the fallback code still being present. Verify which is actually current before relying on the Go/Python paths.

`bitreport` aggregates findings across `bitscope`/`bitprobe`/`bitai` into a unified suite report (`writers/pdf_writer.py`, `json_writer.py`) and has its own Vite/TS dashboard for viewing them.

`skevor.config.json` configures a separate hosted chatbot product ("BitAI"), built on [skevor](https://github.com/rywils/skevor), a multi-tenant AI SaaS framework — a different integration surface than the CLI. `bitai/api/app.py` is a Flask stub whose `/api/bitai/chat` route proxies to a skevor product's `/api/chat`; skevor has no equivalent yet to the old tool-endpoint mapping that would let the agent actually invoke `scan_target`/`fetch_cve`/`verify_vulnerability`/`rule_out_false_positive`/`generate_report` — that needs a real skevor connector, not yet built.

## Data

- CVE data: `bitprobe/scanner/data/cve_db.sqlite` (primary) with `cve_db.json` as fallback/legacy (`cve_db.py`, `cve_db_manager.py`, `cve_updater.py`). Refresh via `bitprobe update-cve-db` (NVD API key recommended, see README).
- ASN/IP intel DB: `asn_db_updater.py`, refreshed via `bitsentry update-db`.
- Neither DB is checked into git (`bitprobe/data/cve_db.sqlite` is gitignored — a prior commit removed a large SQLite file from the repo for this reason).

## Commands

```bash
# Python suite
python bitsentry.py products [--json]
python bitsentry.py scan example.com
python bitsentry.py discover example.com        # bitscope
python bitsentry.py light-scan example.com       # bitprobe only
python bitsentry.py update-db                    # ASN db
python -m pytest                                 # tests/ (pytest.ini: testpaths=tests)

# Rust engine
cd bitprobe/engines/rust/bitprobe_engine && cargo build --release
```

## Conventions

- `from __future__ import annotations` + type hints throughout.
- Tests use plain `pytest` functions with `monkeypatch`, not classes/fixture-heavy setups (see `tests/test_bitscope_subdomain.py`).
- No ORM/database framework — CVE/ASN data is flat SQLite or JSON, read directly.
- Zero TODO/FIXME/HACK markers in the tree as of this onboarding pass — keep it that way rather than leaving debt markers.

## Gotchas

- Rust engine docs vs. fallback code disagree on whether Go/Python scan paths are still supported (see Architecture above).
- Solo-maintainer project (git history has one contributor) — no team conventions to infer beyond what's in code.
