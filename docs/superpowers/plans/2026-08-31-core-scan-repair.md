# Core Scan Repair Implementation Plan

> **For implementers:** Execute this plan task by task with test-first development and review checkpoints.

**Goal:** Restore network scanning, preserve successful reports, propagate detected software versions into CVE matching, and identify long-running checks.

**Architecture:** Validate optional runtime capabilities at their boundaries instead of assuming installed files and dependencies work. Keep existing engine fallback order and result schemas. Repair fingerprint extraction before CVE correlation consumes it.

**Tech Stack:** Python 3.14, pytest, requests, Rust, Go

**Spec:** `docs/superpowers/specs/2026-08-31-core-scan-repair-design.md`

## Global Constraints

- Do not add active SQL injection or XSS probes.
- Do not change scan rate limits.
- Preserve Rust, Go, then Python network engine priority.
- Preserve the existing technology result schema.
- Fail report generation only when every requested format fails.
- Do not modify generated data or changelog files.

---

### Task 1: Reject incompatible Rust executables

**Files:**
- Modify: `bitprobe/scanner/engines/network/__init__.py:32-36`
- Create: `tests/test_bitprobe_network_engine.py`

**Interfaces:**
- Consumes: `RUST_BINARY: pathlib.Path`
- Produces: `_get_rust_binary() -> Optional[Path]`

- [ ] **Step 1: Write the failing executable compatibility test**

```python
from pathlib import Path

from scanner.engines import network


def test_rust_binary_must_run_on_the_current_host(tmp_path, monkeypatch):
    incompatible = tmp_path / "bitprobe-engine"
    incompatible.write_bytes(b"not a native executable")
    incompatible.chmod(0o755)
    monkeypatch.setattr(network, "RUST_BINARY", incompatible)

    assert network._get_rust_binary() is None
```

The production change this catches is returning a path based only on existence.

- [ ] **Step 2: Run the test and verify the current code fails**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_network_engine.py -v`
Expected: FAIL because `_get_rust_binary()` returns the incompatible path.

- [ ] **Step 3: Probe the executable before selecting it**

```python
def _get_rust_binary() -> Optional[Path]:
    if not RUST_BINARY.is_file():
        return None
    try:
        result = subprocess.run(
            [str(RUST_BINARY), "--version"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return RUST_BINARY if result.returncode == 0 else None
```

- [ ] **Step 4: Run the focused test**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_network_engine.py -v`
Expected: PASS.

- [ ] **Step 5: Reproduce fallback behavior through `NetworkScanner`**

Add a test that replaces `_get_go_binary` with `lambda: None`, constructs `NetworkScanner`, and asserts `scanner.engine == "python-native"` while the incompatible Rust path is configured.

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_network_engine.py -v`
Expected: PASS with two tests.

- [ ] **Step 6: Commit the network fix**

```bash
git add bitprobe/scanner/engines/network/__init__.py tests/test_bitprobe_network_engine.py
git commit -m "Fix cross-platform network engine selection"
```

### Task 2: Preserve successful report formats

**Files:**
- Modify: `bitprobe/scanner/reporting/reporter.py:70-89`
- Create: `tests/test_bitprobe_reporter.py`

**Interfaces:**
- Consumes: `Reporter.WRITERS`, requested format names, report dictionary
- Produces: `Reporter.write(...) -> list[str]`

- [ ] **Step 1: Write the failing partial-success test**

```python
from scanner.reporting.reporter import Reporter


def test_reporter_preserves_json_when_pdf_fails(tmp_path, monkeypatch):
    writers = Reporter.WRITERS.copy()
    writers["pdf"] = lambda *_: (_ for _ in ()).throw(RuntimeError("reportlab missing"))
    monkeypatch.setattr(Reporter, "WRITERS", writers)

    artifacts = Reporter.write(
        {"scan_id": "scan_1"},
        "scan_1",
        ["json", "pdf"],
        str(tmp_path),
    )

    assert artifacts == [str((tmp_path / "scan_1.json").resolve())]
    assert (tmp_path / "scan_1.json").is_file()
```

The production change this catches is raising immediately after a later optional writer fails.

- [ ] **Step 2: Write the PDF-only failure test**

```python
import pytest


def test_reporter_fails_when_every_requested_format_fails(tmp_path, monkeypatch):
    writers = Reporter.WRITERS.copy()
    writers["pdf"] = lambda *_: (_ for _ in ()).throw(RuntimeError("reportlab missing"))
    monkeypatch.setattr(Reporter, "WRITERS", writers)

    with pytest.raises(RuntimeError, match="PDF report generation failed"):
        Reporter.write({"scan_id": "scan_1"}, "scan_1", ["pdf"], str(tmp_path))
```

- [ ] **Step 3: Run both tests and verify current behavior**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_reporter.py -v`
Expected: the partial-success test fails while the PDF-only test passes.

- [ ] **Step 4: Collect writer failures and decide after all formats run**

```python
artifacts: List[str] = []
failures: List[str] = []
for fmt in cls.ALLOWED_FORMATS:
    if fmt not in normalized:
        continue
    writer = cls.WRITERS[fmt]
    try:
        artifact = Path(writer(report, str(resolved_output_dir), output_name)).resolve()
        if not artifact.exists():
            raise RuntimeError(f"Failed to write {artifact}")
        print(f"[+] Report written -> {artifact}")
        artifacts.append(str(artifact))
    except Exception as e:
        message = f"{fmt.upper()} report generation failed: {e}"
        failures.append(message)
        print(f"[!] {message}", file=sys.stderr)

if artifacts:
    return artifacts
raise RuntimeError("; ".join(failures) or "No report artifacts were generated")
```

Remove the two unconditional debug prints from the same method.

- [ ] **Step 5: Run focused tests**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_reporter.py -v`
Expected: PASS with two tests.

- [ ] **Step 6: Commit report isolation**

```bash
git add bitprobe/scanner/reporting/reporter.py tests/test_bitprobe_reporter.py
git commit -m "Preserve successful scan reports"
```

### Task 3: Propagate fingerprinted versions into CVE matching

**Files:**
- Modify: `bitprobe/scanner/fingerprints.py:14-118,250-289`
- Create: `tests/test_bitprobe_fingerprints.py`

**Interfaces:**
- Consumes: an HTTP response with server headers and HTML metadata
- Produces: `fingerprint_technologies(response) -> dict` with version fields in `_detailed`

- [ ] **Step 1: Write the failing PHP and WordPress version test**

```python
from requests import Response

from scanner.fingerprints import fingerprint_technologies


def versioned_wordpress_response():
    response = Response()
    response.status_code = 200
    response.url = "https://example.test"
    response.headers = {
        "Content-Type": "text/html",
        "X-Powered-By": "PHP/8.5.5",
    }
    response._content = (
        b'<meta name="generator" content="WordPress 6.7.1">'
        b'<link href="/wp-content/site.css">'
    )
    response.encoding = "utf-8"
    return response


def test_fingerprinting_keeps_php_and_wordpress_versions():
    detected = fingerprint_technologies(versioned_wordpress_response())

    assert detected["framework_version"] == "6.7.1"
    assert detected["_detailed"]["languages"][0] == {
        "name": "PHP",
        "version": "8.5.5",
    }
```

The production change this catches is generic matches preventing later version extraction.

- [ ] **Step 2: Run the test and verify current behavior**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_fingerprints.py::test_fingerprinting_keeps_php_and_wordpress_versions -v`
Expected: FAIL because both version fields are absent.

- [ ] **Step 3: Capture versions and continue version-bearing checks**

Use capturing groups in version signatures:

```python
"WordPress": {
    "body_patterns": [r"wp-content", r"wp-includes", r"wordpress"],
    "headers": {"X-Powered-By": r"PHP/[\d.]+"},
    "meta": [r"WordPress ([\d.]+)"],
},
"PHP": {
    "headers": {"X-Powered-By": r"PHP[/\s]?([\d.]+)"},
    "cookies": [r"PHPSESSID"],
},
```

For header, cookie, and metadata checks, keep an existing detection and fill a missing version:

```python
if not detected or version is None:
    found, candidate_version = check_headers(...)
    if found:
        detected = True
        version = version or candidate_version
```

Apply the same version capture pattern to Apache, Nginx, and IIS signatures.

- [ ] **Step 4: Run the fingerprint test**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_fingerprints.py -v`
Expected: PASS.

- [ ] **Step 5: Write the failing CVE propagation test**

```python
from plugins import cve_correlation
from plugins.cve_correlation import CVECorrelationPlugin


def test_cve_correlation_uses_the_fingerprinted_php_version(monkeypatch):
    response = versioned_wordpress_response()

    class Handler:
        def get(self, _url):
            return response

    def query_cves(_name, version=None):
        if version != "8.5.5":
            return []
        return [{
            "cve_id": "CVE-2026-17543",
            "cvss_score": 9.8,
            "confidence": "confirmed",
            "description": "PHP test advisory",
            "references": [],
            "kev": False,
            "kev_date_added": None,
            "epss_score": None,
            "epss_percentile": None,
        }]

    monkeypatch.setattr(cve_correlation, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(cve_correlation, "query_cves", query_cves)

    findings = CVECorrelationPlugin().scan(
        {"url": response.url, "depth": 0},
        Handler(),
    )

    assert [finding.evidence["cve_id"] for finding in findings] == ["CVE-2026-17543"]
```

- [ ] **Step 6: Run the CVE propagation test**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_fingerprints.py -v`
Expected: PASS after the fingerprint fix and FAIL if PHP version extraction is removed.

- [ ] **Step 7: Commit version propagation**

```bash
git add bitprobe/scanner/fingerprints.py tests/test_bitprobe_fingerprints.py
git commit -m "Fix version-aware CVE fingerprinting"
```

### Task 4: Identify pending plugin checks

**Files:**
- Modify: `bitprobe/scanner/engine.py:16,309-365`
- Create: `tests/test_bitprobe_progress.py`

**Interfaces:**
- Consumes: pending futures mapped to `(plugin, url_info, started_at)`
- Produces: `_pending_plugin_status(...) -> str`

- [ ] **Step 1: Write the failing status formatting test**

```python
from scanner.engine import _pending_plugin_status


class Plugin:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


def test_pending_status_names_checks_and_elapsed_time():
    first = object()
    second = object()
    tasks = {
        first: (Plugin("sensitive_files"), {"url": "https://one.test"}, 10.0),
        second: (Plugin("cve_correlation"), {"url": "https://two.test"}, 12.0),
    }

    assert _pending_plugin_status({first, second}, tasks, now=17.9) == (
        "cve_correlation, sensitive_files (7s elapsed)"
    )
```

The production change this catches is replacing actionable pending names with a generic count.

- [ ] **Step 2: Run the test and verify the helper is missing**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_progress.py -v`
Expected: collection error because `_pending_plugin_status` does not exist.

- [ ] **Step 3: Add the production formatter and timestamps**

```python
def _pending_plugin_status(pending, future_to_task, now=None) -> str:
    now = time.monotonic() if now is None else now
    names = sorted({future_to_task[future][0].get_name() for future in pending})
    oldest = min(future_to_task[future][2] for future in pending)
    return f"{', '.join(names)} ({int(now - oldest)}s elapsed)"
```

Store `time.monotonic()` with each submitted task.
Use the helper in the five-second wait message.
Update tuple unpacking where completed futures are processed.

- [ ] **Step 4: Run the focused progress test**

Run: `PYTHONPATH=bitprobe pytest tests/test_bitprobe_progress.py -v`
Expected: PASS.

- [ ] **Step 5: Commit progress output**

```bash
git add bitprobe/scanner/engine.py tests/test_bitprobe_progress.py
git commit -m "Show pending scanner checks"
```

### Task 5: Verify the complete repair

**Files:**
- Test: all files created above
- Verify: `bitprobe/engines/rust/bitprobe_engine/Cargo.toml`

**Interfaces:**
- Consumes: completed Tasks 1 through 4
- Produces: verified local scan behavior

- [ ] **Step 1: Run focused regression tests**

Run:

```bash
PYTHONPATH=bitprobe pytest \
  tests/test_bitprobe_network_engine.py \
  tests/test_bitprobe_reporter.py \
  tests/test_bitprobe_fingerprints.py \
  tests/test_bitprobe_progress.py -v
```

Expected: all focused tests pass.

- [ ] **Step 2: Run the full Python suite**

Run: `pytest -q`
Expected: zero failures.

- [ ] **Step 3: Run syntax and style checks configured by the repository**

Run: `python -m compileall -q bitsentry.py bitprobe tests`
Expected: exit 0.

Run: `git diff --check`
Expected: no output and exit 0.

- [ ] **Step 4: Build Rust without touching the tracked release artifact**

Run:

```bash
CARGO_TARGET_DIR=/tmp/bitsentry-rust-target \
  cargo build --release \
  --manifest-path bitprobe/engines/rust/bitprobe_engine/Cargo.toml
```

Expected: exit 0.

- [ ] **Step 5: Run the local end-to-end vulnerable fixture**

Start a local HTTP fixture that returns `X-Powered-By: PHP/8.5.5` and WordPress `6.7.1` metadata.
Run BitProbe with `fingerprinting,cve_correlation,network_scanner` and `json,pdf` output into a temporary directory.
Assert:

- process exit is 0
- JSON exists
- PDF absence is a warning when `reportlab` is unavailable
- fingerprint evidence contains PHP `8.5.5` and WordPress `6.7.1`
- CVE findings contain the locally available PHP advisories
- network scanning does not raise `Exec format error`

- [ ] **Step 6: Inspect repository state**

Run: `git status --short`
Expected: only the pre-existing `bitprobe/data/asn_db.json` and `.codex/` changes remain outside committed repair work.
