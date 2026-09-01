<p align="center">
  <img src="./BitSentry.png" alt="BitSentry logo" width="220" />
</p>

# BitSentry

BitSentry is a CLI-first security assessment suite. The public build focuses on two production-ready capabilities:

- external attack-surface discovery
- web-focused vulnerability scanning

It is built to run cleanly in local shells, CI pipelines, and Docker.
Supported hosts are Linux and macOS.
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

# 2) CVE database: verified snapshot, then incremental NVD catch-up
bitsentry update-cve-db

# Check what was loaded
bitsentry cve-stats

# 3) Run your first assessment
bitsentry scan example.com
```

**Ongoing maintenance:**

```bash
bitsentry update-db              # refresh ASN data when stale
bitsentry update-cve-db          # snapshot if needed, otherwise incremental sync
```

If you skip this step, the first scan uses the same snapshot bootstrap automatically. See [CVE database](#cve-database) for direct-NVD and offline fallback behavior.

### Option 2: manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Same post-install DB steps as Option 1 (use python bitsentry.py if bitsentry is not on PATH)
python bitsentry.py update-db
python bitsentry.py update-cve-db
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

BitProbe stores mutable CVE data in `~/.bitsentry/data/cve_db.sqlite` and matches CVEs by detected product and version. Set `BITSENTRY_DATA_DIR` to use a different data directory.

| Phase | What happens |
|---|---|
| **Bootstrap** | Downloads and verifies the published full-corpus snapshot |
| **Incremental sync** | Fetches only NVD records modified since the last cursor (fast) |
| **Scan** | Fingerprints the target, then queries the DB for that product/CPE |

The default command installs a verified snapshot when the database is missing or incomplete, then fetches changes made after the snapshot cursor:

```bash
python bitsentry.py update-cve-db

# Install the snapshot without an incremental NVD catch-up
python bitsentry.py update-cve-db --snapshot-only

# Inspect local coverage and counts
python bitsentry.py cve-stats
```

Direct-NVD modes skip the snapshot. BitSentry splits long NVD date ranges into 119-day windows:

```bash
# Rebuild the complete corpus directly from NVD
python bitsentry.py update-cve-db --full

# Raw unfiltered crawl (best-effort offset resumption)
python bitsentry.py update-cve-db --raw-full

# Build partial publication-window databases
python bitsentry.py update-cve-db --days 30
python bitsentry.py update-cve-db --years 15

# Synchronize directly without downloading a snapshot
python bitsentry.py update-cve-db --no-snapshot

# Skip automatic CVE refresh at scan startup
export BITSENTRY_SKIP_CVE_UPDATE=1
```

Set `NVD_API_KEY` for the higher NVD request limit. Interrupted windowed updates resume from the last committed page. BitSentry checksum-verifies snapshots and installs them atomically. If the snapshot is unavailable on an empty installation, it falls back to a 30-day publication database and warns that coverage is partial.

Direct product commands are also available via `python bitprobe/bitprobe.py ...` with the same flags.

### Other maintenance

```bash
python bitsentry.py profiles

# Bounded active web vulnerability checks
python bitsentry.py scan https://example.com --profile safe-active
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

Implementation direction: Python remains the orchestration core; performance-sensitive components may continue to move into compiled tooling (Go/Rust/Zig) where appropriate.

## License

- MIT (`LICENSE`)
