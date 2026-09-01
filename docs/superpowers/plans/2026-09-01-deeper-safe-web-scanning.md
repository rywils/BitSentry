# Deeper Safe Web Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add modular, bounded, safe-active web vulnerability checks beyond the current XSS, SQL error, traversal, and redirect probes.

**Architecture:** Keep `WebVulnerabilitiesPlugin` as the coordinator and move detector logic into focused check modules. A shared request budget and validated request callback enforce limits before detector-specific probes run.

**Tech Stack:** Python, requests, BeautifulSoup, pytest, existing `Finding` and `RequestHandler` types.

**Spec:** `docs/superpowers/specs/2026-09-01-deeper-safe-web-scanning-design.md`

## Global Constraints

- HTTP methods are GET only.
- Active requests use `allow_redirects=False`.
- Requests remain same-origin after `requests.Request(...).prepare()` normalization.
- Default safe-active budget is 24 requests per endpoint and 240 requests per origin.
- SSRF checks require an explicit configured canary host.
- Evidence excludes original values, credentials, cookies, authorization headers, and full response bodies.
- Grouping occurs before prioritization, attack-chain construction, statistics, and reports.

---

### Task 1: Add shared active-scan budget and request context

**Files:**
- Create: `bitprobe/scanner/active_checks/context.py`
- Create: `tests/test_active_scan_context.py`

**Interfaces:**
- Produces `ActiveScanContext(endpoint: str, origin: tuple, baseline, params: dict, request, endpoint_budget: int = 24, origin_budget: int = 240)`.
- Produces `ActiveScanContext.probe(params: dict, *, module: str)` returning a response or `None`.
- Produces `ActiveScanContext.can_probe(module: str) -> bool` and `ActiveScanContext.usage() -> dict`.

- [ ] **Step 1: Write failing tests**

```python
def test_context_rejects_budget_exhaustion():
    context = ActiveScanContext("https://example.test/", ("https", "example.test", 443), None, {"q": "x"}, lambda **_: object(), endpoint_budget=1)
    assert context.probe({"q": "one"}, module="xss") is not None
    assert context.probe({"q": "two"}, module="xss") is None
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_active_scan_context.py -v`
Expected: FAIL because the context module does not exist.

- [ ] **Step 3: Implement minimal context**

Use a set of `(module, frozen parameter values)` keys, increment endpoint and origin counters only after a request is admitted, and return `None` once either budget is exhausted.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_active_scan_context.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bitprobe/scanner/active_checks/context.py tests/test_active_scan_context.py
git commit -m "Add bounded active scan context"
```

### Task 2: Split existing checks into detector modules

**Files:**
- Create: `bitprobe/scanner/active_checks/reflected_xss.py`
- Create: `bitprobe/scanner/active_checks/sql_errors.py`
- Create: `bitprobe/scanner/active_checks/traversal.py`
- Create: `bitprobe/scanner/active_checks/redirects.py`
- Modify: `bitprobe/plugins/web_vulnerabilities.py`
- Test: `tests/test_web_vulnerabilities.py`

**Interfaces:**
- Each module exports `check(context: ActiveScanContext, parameter: str) -> list[Finding]`.
- The coordinator creates one context per discovered endpoint and delegates checks in deterministic module order.

- [ ] **Step 1: Add delegation tests**

```python
def test_coordinator_uses_named_check_modules(monkeypatch):
    called = []
    monkeypatch.setattr("plugins.web_vulnerabilities.CHECKS", [lambda *_: called.append(True) or []])
    WebVulnerabilitiesPlugin().scan({"url": "https://example.test/?q=x", "depth": 0}, Handler())
    assert called == [True]
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_web_vulnerabilities.py::test_coordinator_uses_named_check_modules -v`
Expected: FAIL because `CHECKS` and module delegation do not exist.

- [ ] **Step 3: Move existing detector logic without behavior changes**

Preserve titles, severity, remediation, baseline comparisons, redacted SQL evidence, and redirect controls.

- [ ] **Step 4: Run existing active tests**

Run: `pytest tests/test_web_vulnerabilities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bitprobe/scanner/active_checks bitprobe/plugins/web_vulnerabilities.py tests/test_web_vulnerabilities.py
git commit -m "Split active checks into modules"
```

### Task 3: Add command injection, SSTI, and file inclusion checks

**Files:**
- Create: `bitprobe/scanner/active_checks/command_injection.py`
- Create: `bitprobe/scanner/active_checks/ssti.py`
- Create: `bitprobe/scanner/active_checks/file_inclusion.py`
- Modify: `bitprobe/plugins/web_vulnerabilities.py`
- Create or modify: `tests/test_deeper_web_checks.py`

**Interfaces:**
- Each module exports `check(context: ActiveScanContext, parameter: str) -> list[Finding]`.
- Command injection uses a fixed non-timing marker and reports only when the marker appears newly in the response.
- SSTI uses arithmetic markers such as `7*7` and reports only when `49` appears newly in the response.
- File inclusion uses bounded Unix and Windows file signatures and reports only when newly introduced.

- [ ] **Step 1: Write positive and negative fixture tests**

```python
def test_command_injection_requires_new_marker():
    findings, _ = scan("cmd", lambda params: response("uid=1000" if "bitsentry-cmd" in params["cmd"] else "safe"))
    assert any("Command Injection" in item.title for item in findings)


def test_ssti_requires_evaluated_expression():
    findings, _ = scan("template", lambda params: response("49" if "7*7" in params["template"] else "7*7"))
    assert any("Template Injection" in item.title for item in findings)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_deeper_web_checks.py -v`
Expected: FAIL because the new modules are absent.

- [ ] **Step 3: Implement bounded detectors**

Use one payload class per parameter until a signal is found, never use timing, and store only payload class and bounded signatures in evidence.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_deeper_web_checks.py tests/test_web_vulnerabilities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bitprobe/scanner/active_checks bitprobe/plugins/web_vulnerabilities.py tests/test_deeper_web_checks.py
git commit -m "Add deeper safe web detectors"
```

### Task 4: Add adaptive discovery and JSON GET parameters

**Files:**
- Modify: `bitprobe/plugins/web_vulnerabilities.py`
- Modify: `tests/test_web_vulnerabilities.py`

**Interfaces:**
- `discover_get_targets()` preserves repeated values and returns top-level JSON keys only for JSON responses supplied to the coordinator.
- The coordinator skips duplicate endpoint, parameter, and payload combinations.

- [ ] **Step 1: Write discovery and budget tests**

```python
def test_json_get_target_discovers_top_level_keys():
    targets = discover_json_targets("https://example.test/api?query=ok", '{"query":"ok","nested":{"secret":"x"}}')
    assert targets == [("https://example.test/api", {"query": "ok"})]
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_web_vulnerabilities.py::test_json_get_target_discovers_top_level_keys -v`
Expected: FAIL because JSON discovery is not implemented.

- [ ] **Step 3: Implement JSON discovery and adaptive admission**

Add JSON content-type gating, preserve only top-level scalar values, and admit follow-up probes only after a module-specific signal.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_web_vulnerabilities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bitprobe/plugins/web_vulnerabilities.py tests/test_web_vulnerabilities.py
git commit -m "Expand safe parameter discovery"
```

### Task 5: Add profiles, progress, documentation, and end-to-end fixtures

**Files:**
- Modify: `bitprobe/scanner/config.py`
- Modify: `bitprobe/scanner/engine.py`
- Modify: `bitprobe/README.md`
- Modify: `README.md`
- Create or modify: `tests/test_bitprobe_active_config.py`
- Create: `tests/test_deeper_scan_e2e.py`

**Interfaces:**
- Safe active mode is selectable independently from passive quick scanning.
- Progress reports module, endpoint, parameter, completed requests, and budget usage.
- A local fixture verifies positive and negative behavior for every detector and confirms grouped findings.

- [ ] **Step 1: Write profile and E2E tests**

```python
def test_safe_active_profile_is_explicit():
    config = ScanConfig("https://example.test", profile="safe-active")
    assert "web_vulnerabilities" in config.enabled_plugins
    assert config.active_scan_mode == "safe"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_bitprobe_active_config.py::test_safe_active_profile_is_explicit -v`
Expected: FAIL because the profile is not defined.

- [ ] **Step 3: Implement profile and progress plumbing**

Keep passive quick behavior unchanged, add a safe-active profile, and thread bounded progress callbacks through the existing scan engine.

- [ ] **Step 4: Run all verification**

Run: `pytest -q`
Run: `python -m compileall -q bitsentry.py bitprobe tests`
Run: `git diff --check`
Run: `cargo build --release --manifest-path bitprobe/engines/rust/bitprobe_engine/Cargo.toml`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add bitprobe/scanner/config.py bitprobe/scanner/engine.py bitprobe/README.md README.md tests
git commit -m "Expose safe active scanning profile"
```
