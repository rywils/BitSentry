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

# full workflow (default)
bitsentry scan example.com
```

### Option 2: manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

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

```bash
python bitsentry.py update-db
python bitsentry.py update-cve-db --days 30
python bitsentry.py cve-stats
python bitsentry.py profiles
```

Direct product commands are also available via `python bitprobe/bitprobe.py ...`.

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
