# Active Web Scanning Implementation Plan

**Goal:** Add grouped severity-ordered reporting and bounded GET-based application vulnerability checks.

**Spec:** `docs/superpowers/specs/2026-08-31-active-web-scanning-design.md`

## Constraints

- Use test-first development.
- Send no state-changing POST requests.
- Follow no external redirects.
- Keep active evidence bounded and free of credentials.
- Preserve the existing finding schema while adding grouped endpoint fields.
- Preserve user ASN database changes.

### Task 1: Group and order findings

**Files:**
- Create: `bitprobe/scanner/analysis/findings.py`
- Create: `tests/test_bitprobe_finding_groups.py`
- Modify: `bitprobe/scanner/engine.py`

- [ ] Add failing tests proving equivalent findings collapse into one sorted `affected_endpoints` list.
- [ ] Add failing tests proving severity, title, and endpoint ordering.
- [ ] Implement `group_findings(findings: list[dict]) -> list[dict]`.
- [ ] Call aggregation before prioritization in `_generate_report`.
- [ ] Assert grouped totals and risk count each vulnerability once.
- [ ] Run focused tests.

### Task 2: Render grouped endpoints

**Files:**
- Modify: `bitprobe/scanner/reporting/markdown_report.py`
- Modify: `bitprobe/scanner/reporting/pdf_report.py`
- Create: `tests/test_bitprobe_grouped_reports.py`

- [ ] Add failing Markdown tests for one section with sorted endpoint bullets.
- [ ] Add failing PDF story tests for grouped endpoint text.
- [ ] Render `affected_endpoints` with `url` fallback.
- [ ] Run focused report tests.

### Task 3: Detect active GET vulnerabilities

**Files:**
- Create: `bitprobe/plugins/web_vulnerabilities.py`
- Create: `tests/test_web_vulnerabilities.py`

- [ ] Add failing tests for query and GET-form input discovery.
- [ ] Add failing reflected XSS detection and escaped-reflection rejection tests.
- [ ] Add failing SQL error baseline-difference tests.
- [ ] Add failing Unix and Windows traversal tests.
- [ ] Add failing open redirect exact-location and no-follow tests.
- [ ] Add failing request-cap and same-origin tests.
- [ ] Implement the smallest plugin that passes these checks.
- [ ] Run focused plugin tests.

### Task 4: Load and verify the active plugin

**Files:**
- Modify: `bitprobe/scanner/config.py`
- Modify: `bitprobe/scanner/engine.py`
- Modify: `bitprobe/README.md`
- Create: `tests/test_bitprobe_active_config.py`

- [ ] Add failing tests for default, standard, full, quick, and infrastructure plugin selection.
- [ ] Register `web_vulnerabilities` in the engine and approved profiles.
- [ ] Document active coverage and exclusions.
- [ ] Run a local vulnerable HTTP fixture through the command line.
- [ ] Verify grouped JSON, Markdown, and PDF output.
- [ ] Run all Python tests, compile checks, diff checks, and the Rust release build.
