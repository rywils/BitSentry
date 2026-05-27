<p align="center">
  <img src="./BitSentry.png" alt="BitSentry logo" width="220" />
</p>

# BitSentry

BitSentry is a CLI-first security assessment suite. The public build focuses on two production-ready capabilities:

- external attack-surface discovery
- web-focused vulnerability scanning

It is built to run cleanly in local shells, CI pipelines, and Docker. A private edition includes a Web UI with parity to CLI workflows; that UI is not part of this public repository.

> Use only on systems you own or are explicitly authorized to test.

## Current Product Status

| Product | Purpose | Status |
|---|---|---|
| `bitsentry` | Suite orchestrator and unified CLI | Implemented |
| `bitscope` | Subdomain/cloud/IP discovery | Implemented |
| `bitprobe` | Crawl + plugin-based vulnerability scanning | Implemented |
| `bitreport` | Aggregated suite reporting | Implemented |
| `bitai` | Verification helpers | Implemented (expanding) |
| `bitwatch`, `bitgraph`, `bitintel`, `bitspear`, `bitcannon` | Planned suite modules | Scaffold |

Live registry:

```bash
python bitsentry.py products
python bitsentry.py products --json
```

## Quick Start

### Option 1 (recommended): installer

```bash
./scripts/install_bitsentry.sh

# first load after install (if needed)
# zsh:  source ~/.zshrc && hash -r
# bash: source ~/.bashrc && hash -r   (or ~/.bash_profile on macOS)
# fish: set -U fish_user_paths /usr/local/bin $fish_user_paths

# verify
bitsentry --help
```

### After install (before your first scan)

Refresh local intelligence databases once so scans are useful. This is separate from `install_bitsentry.sh` (the installer may remind you about ASN data but does not download CVE data).

```bash
# 1) ASN database (fast; needed for ASN/IP intel plugins)
bitsentry update-db

# 2) CVE database (choose one bootstrap — required for technology/CVE correlation)
export NVD_API_KEY="your-nvd-api-key"   # optional but strongly recommended

# Recommended: full local mirror (slow once; best coverage)
bitsentry update-cve-db --full

# Alternative: smaller first-time bootstrap (~15 years of publications)
# bitsentry update-cve-db --years 15

# Check what was loaded
bitsentry cve-stats

# 3) Run your first assessment
bitsentry scan example.com
```

**Ongoing maintenance** (after the one-time bootstrap above):

```bash
bitsentry update-db              # refresh ASN data when stale
bitsentry update-cve-db          # incremental CVE sync (fast)
```

If you skip CVE bootstrap, the first scan may still run but will only auto-fetch a **short recent-publication window**—not enough for historical product/CVE exposure. See [CVE database](#cve-database) below for details.

### Option 2: manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Same post-install DB steps as Option 1 (use python bitsentry.py if bitsentry is not on PATH)
python bitsentry.py update-db
export NVD_API_KEY="your-nvd-api-key"   # optional
python bitsentry.py update-cve-db --full   # or: --years 15
python bitsentry.py cve-stats

# Full workflow (default): BitScope discovery -> BitProbe scan
python bitsentry.py scan example.com

# Discovery only
python bitsentry.py discover example.com

# scanner-only (BitProbe path)
python bitsentry.py light-scan https://example.com
# equivalent
python bitsentry.py bitprobe scan https://example.com
```

### Important behavior

- `scan` = default full suite workflow
- `full-scan` remains as a compatibility alias
- `light-scan` = BitProbe-only path
- apex and `www` are treated as same site during crawl scope
- redundant `www.<apex>` follow-on targets are avoided in suite scans

## Installer details

The installer:

- creates or reuses `.env`
- creates/repairs `.venv`
- installs runtime dependencies from `requirements.txt`
- installs a launcher in an OS-appropriate bin directory
- prints local ASN DB status and suggests `bitsentry update-db` if stale

It does **not** download or build the CVE database. Follow [After install (before your first scan)](#after-install-before-your-first-scan) before relying on CVE correlation in scan results.

## Docker

Portable CLI usage without local Python dependency:

```bash
docker build -t bitsentry .
docker run --rm bitsentry --help
docker run --rm bitsentry scan example.com
```

Persist artifacts to host:

```bash
mkdir -p ./bitsentry-out
docker run --rm -v "$(pwd)/bitsentry-out:/out" bitsentry scan example.com --suite-out /out
```

Compose path:

```bash
docker compose build
docker compose run --rm bitsentry --help
docker compose run --rm bitsentry scan example.com
```

## Data Maintenance Commands

### ASN database

```bash
python bitsentry.py update-db          # alias: update-asn-db
```

### CVE database

BitProbe stores CVEs in a local SQLite database (`bitprobe/data/cve_db.sqlite`) and matches them **by detected product and version** during scans—not by “CVEs published in the last N days.”

| Phase | What happens |
|---|---|
| **Bootstrap** | Populates the local DB (one-time or after a wipe) |
| **Incremental sync** | Fetches only NVD records modified since the last cursor (fast) |
| **Scan** | Fingerprints the target, then queries the DB for that product/CPE |

A short publication window (for example `--days 30`) only controls **what gets downloaded into the DB**. It does not limit scan logic. For real exposure coverage, bootstrap with a full or multi-year mirror first, then rely on incremental updates.

**Recommended first-time setup:**

```bash
# Optional but strongly recommended (higher NVD rate limits)
export NVD_API_KEY="your-nvd-api-key"

# One-time: build a complete local mirror (slow; ~350k CVEs)
python bitsentry.py update-cve-db --full

# Alternative: compromise bootstrap (~15 years of publications)
python bitsentry.py update-cve-db --years 15

# Ongoing refresh (incremental when a sync cursor exists)
python bitsentry.py update-cve-db

# Inspect local store
python bitsentry.py cve-stats
```

**Other options:**

```bash
# Quick bootstrap only (~recent publications; not sufficient alone for deep history)
python bitsentry.py update-cve-db --days 30

# Skip automatic CVE refresh at scan startup
export BITSENTRY_SKIP_CVE_UPDATE=1
```

On scan startup, if the DB is empty, BitProbe may run a **7-day publication bootstrap** so the tool stays usable without blocking on a full NVD download. Run `update-cve-db --full` or `--years 15` before relying on CVE findings in production assessments.

Direct product commands are also available via `python bitprobe/bitprobe.py ...` (same flags: `--full`, `--years`, `--days`).

### Other maintenance

```bash
python bitsentry.py profiles
```

## Suite Output and Reporting

Full run with aggregated artifacts:

```bash
python bitsentry.py scan example.com \
  --suite-out ./suite_runs \
  --suite-report \
  --suite-verify
```

Report formats:

- BitProbe: `json`, `md`, `pdf`, `html`
- BitScope: `json`, `yaml`, `table`

Note on public HTML output: the `.html` artifact is a placeholder page in this public repository; use JSON/Markdown/PDF for report content.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

## Roadmap

Short term: complete and integrate scaffold modules (`bitwatch`, `bitgraph`, `bitintel`, `bitspear`, `bitcannon`).

Private product line: includes Web UI and broader integrations (SSO, workflow hooks, exports, and operational connectors) while keeping capability parity with CLI operations.

Implementation direction: Python remains the orchestration core; performance-sensitive components may continue to move into compiled tooling (Go/Rust/Zig) where appropriate.

## License

- MIT (`LICENSE`)
